//! Captura passiva de rede da secao Kernel Exploring.
//!
//! Abre um socket RAW do Winsock numa interface IPv4 e liga o modo
//! `SIO_RCVALL` (promiscuo a nivel de IP). Cada pacote IPv4 e dissecado no
//! cabecalho — IPs, portas, protocolo e tamanho — e os primeiros bytes do
//! datagrama sao guardados para inspecao estilo Wireshark (hex/ASCII dump e
//! preview de HTTP em texto puro). Em paralelo, um poller le as tabelas TCP/UDP
//! do Windows (IP Helper) para atribuir cada conversa ao PROCESSO dono do
//! socket. Nao toca no processo alvo: funciona com qualquer jogo, inclusive sob
//! anticheat kernel.
//!
//! Atencao: o conteudo de conexoes HTTPS e ciphertext TLS — aparece como hex
//! cifrado, exatamente como no Wireshark sem a chave. Para ver path/URL/body
//! decodificados use o proxy MITM (aba Proxy).
//!
//! Roda em threads proprias; a GUI le os agregados via [`CaptureShared`]. Precisa
//! de privilegios de Administrador (o Quarry ja exige isso).

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::BOOL;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{
    bind, closesocket, recv, setsockopt, socket, WSACleanup, WSAGetLastError, WSAIoctl, WSAStartup,
    ADDRESS_FAMILY, AF_INET, INVALID_SOCKET, IN_ADDR, IN_ADDR_0, IPPROTO_IP, SEND_RECV_FLAGS,
    SIO_RCVALL, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO,
    WSADATA, WSAETIMEDOUT,
};

/// Chave que identifica uma conversa: (protocolo, porta local, IP remoto, porta remota).
pub type ConvKey = (u8, u16, Ipv4Addr, u16);

/// Uma "conversa" agregada por [`ConvKey`], ja atribuida a um processo.
#[derive(Clone)]
pub struct Conversation {
    pub proto: u8,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    /// PID do processo dono do socket (0 = ainda desconhecido).
    pub pid: u32,
    /// Nome do executavel dono do socket (vazio se desconhecido).
    pub process: String,
    pub packets: u64,
    pub bytes: u64,
    pub last_ms: u64,
}

impl Conversation {
    pub fn proto_name(&self) -> &'static str {
        proto_name(self.proto)
    }

    pub fn key(&self) -> ConvKey {
        (self.proto, self.local_port, self.remote_ip, self.remote_port)
    }
}

/// Um pacote IPv4 individual, com os primeiros bytes preservados para dump.
#[derive(Clone)]
pub struct PacketRecord {
    /// Timestamp relativo ao inicio da captura, em milissegundos.
    pub ts_ms: u64,
    /// `true` = saindo da nossa interface, `false` = entrando.
    pub outbound: bool,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Tamanho total do datagrama IP (do cabecalho, antes de truncar).
    pub total_len: u16,
    /// Pacote IP (cabecalho + payload), truncado em [`MAX_PKT_BYTES`].
    pub data: Vec<u8>,
}

impl PacketRecord {
    pub fn proto_name(&self) -> &'static str {
        proto_name(self.proto)
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "IP",
    }
}

/// Nome do protocolo para uso na GUI (breadcrumb etc.).
pub fn proto_label(proto: u8) -> &'static str {
    proto_name(proto)
}

/// Indice (porta/IP) -> PID, alimentado pelas tabelas TCP/UDP do Windows.
#[derive(Default)]
struct ProcIndex {
    /// TCP estabelecido: (porta local, IP remoto, porta remota) -> PID.
    tcp: HashMap<(u16, Ipv4Addr, u16), u32>,
    /// Fallback por porta local (listeners, conexoes ainda nao casadas).
    tcp_by_lport: HashMap<u16, u32>,
    /// UDP e sem conexao: so da pra casar por porta local.
    udp_by_lport: HashMap<u16, u32>,
    /// PID -> nome do executavel.
    names: HashMap<u32, String>,
}

/// Estado compartilhado entre a GUI e as threads de captura.
pub struct CaptureShared {
    pub convs: Mutex<Vec<Conversation>>,
    /// Pacotes recentes por conversa (ring buffer limitado).
    pub packets: Mutex<HashMap<ConvKey, VecDeque<PacketRecord>>>,
    proc_index: Mutex<ProcIndex>,
    pub total_packets: AtomicU64,
    pub total_bytes: AtomicU64,
    running: AtomicBool,
}

/// Handle da captura em execucao, mantido pela GUI. O Drop encerra as threads.
pub struct CaptureHandle {
    pub shared: Arc<CaptureShared>,
    status: Arc<Mutex<String>>,
}

impl CaptureHandle {
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.shared.running.store(false, Ordering::Relaxed);
    }
}

/// Limite de conversas distintas guardadas (evita crescer sem fim).
const MAX_CONVS: usize = 4000;
/// Pacotes guardados por conversa (os mais antigos sao descartados).
pub const MAX_PKTS_PER_CONV: usize = 200;
/// Bytes preservados por pacote para o hex dump.
const MAX_PKT_BYTES: usize = 1600;

/// Descobre o IPv4 da interface de saida primaria (o "truque do UDP connect":
/// nenhum pacote e enviado, mas o SO escolhe a rota e revela o IP local).
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// Sobe a captura (thread de recv + thread de atribuicao de processo) e devolve
/// o handle imediatamente.
pub fn start(iface: Ipv4Addr) -> CaptureHandle {
    let shared = Arc::new(CaptureShared {
        convs: Mutex::new(Vec::new()),
        packets: Mutex::new(HashMap::new()),
        proc_index: Mutex::new(ProcIndex::default()),
        total_packets: AtomicU64::new(0),
        total_bytes: AtomicU64::new(0),
        running: AtomicBool::new(true),
    });
    let status = Arc::new(Mutex::new(String::from("iniciando…")));

    // Thread de captura.
    let shared_c = shared.clone();
    let status_c = status.clone();
    std::thread::spawn(move || {
        if let Err(e) = capture_loop(iface, &shared_c, &status_c) {
            *status_c.lock().unwrap() = format!("erro: {e}");
            shared_c.running.store(false, Ordering::Relaxed);
        }
    });

    // Thread que mapeia sockets -> processos (IP Helper), atualizando ~1x/s.
    let shared_p = shared.clone();
    std::thread::spawn(move || {
        while shared_p.running.load(Ordering::Relaxed) {
            refresh_proc_index(&shared_p.proc_index);
            // dorme ~1s, mas reavalia o flag de parada a cada 100ms
            for _ in 0..10 {
                if !shared_p.running.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });

    CaptureHandle { shared, status }
}

/// Loop de recepcao. Roda ate `running` virar false (checado a cada timeout).
fn capture_loop(
    iface: Ipv4Addr,
    shared: &Arc<CaptureShared>,
    status: &Arc<Mutex<String>>,
) -> Result<(), String> {
    unsafe {
        let mut wsadata = WSADATA::default();
        if WSAStartup(0x0202, &mut wsadata) != 0 {
            return Err("WSAStartup falhou".into());
        }
        // garante WSACleanup ao sair, qualquer que seja o caminho
        let _cleanup = WsaCleanupGuard;

        let sock = socket(AF_INET.0 as i32, SOCK_RAW, IPPROTO_IP.0)
            .map_err(|e| format!("socket() falhou: {e}"))?;
        if sock == INVALID_SOCKET {
            return Err(format!("socket() falhou (erro {})", WSAGetLastError().0));
        }
        let _closer = SocketGuard(sock);

        // bind na interface escolhida (obrigatorio para SIO_RCVALL)
        let addr = SOCKADDR_IN {
            sin_family: ADDRESS_FAMILY(AF_INET.0),
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(iface.octets()),
                },
            },
            sin_zero: [0; 8],
        };
        if bind(
            sock,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) == SOCKET_ERROR
        {
            return Err(format!(
                "bind({iface}) falhou (erro {}). Use o IP de uma placa de rede real.",
                WSAGetLastError().0
            ));
        }

        // timeout de recv para poder checar o flag de parada
        let timeout_ms: u32 = 500;
        let _ = setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            Some(&timeout_ms.to_ne_bytes()),
        );

        // liga o modo promiscuo a nivel IP (recebe todo trafego da interface)
        let optval: u32 = 1; // RCVALL_ON
        let mut bytes_ret: u32 = 0;
        if WSAIoctl(
            sock,
            SIO_RCVALL,
            Some(&optval as *const u32 as *const _),
            std::mem::size_of::<u32>() as u32,
            None,
            0,
            &mut bytes_ret,
            None,
            None,
        ) == SOCKET_ERROR
        {
            return Err(format!(
                "SIO_RCVALL falhou (erro {}). Rode como Administrador.",
                WSAGetLastError().0
            ));
        }

        *status.lock().unwrap() = format!("capturando em {iface}");

        let start = Instant::now();
        let mut buf = [0u8; 65535];
        while shared.running.load(Ordering::Relaxed) {
            let n = recv(sock, &mut buf, SEND_RECV_FLAGS(0));
            if n == SOCKET_ERROR {
                let err = WSAGetLastError();
                if err == WSAETIMEDOUT {
                    continue; // so um tick para reavaliar o flag de parada
                }
                return Err(format!("recv falhou (erro {})", err.0));
            }
            if n <= 0 {
                continue;
            }
            let ms = start.elapsed().as_millis() as u64;
            ingest(iface, &buf[..n as usize], ms, shared);
        }
    }
    Ok(())
}

/// Dissecca um pacote IPv4, atualiza os agregados e guarda o pacote bruto.
fn ingest(iface: Ipv4Addr, pkt: &[u8], ms: u64, shared: &Arc<CaptureShared>) {
    if pkt.len() < 20 {
        return;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as u64;

    // portas para TCP (6) / UDP (17): primeiros 4 bytes do cabecalho L4
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if (proto == 6 || proto == 17) && pkt.len() >= ihl + 4 {
        src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    }

    // determina lado local vs remoto pela interface
    let outbound = src == iface;
    let (local_port, remote_ip, remote_port) = if outbound {
        (src_port, dst, dst_port)
    } else if dst == iface {
        (dst_port, src, src_port)
    } else {
        // nem entrada nem saida pela nossa interface (broadcast/multicast)
        (src_port, dst, dst_port)
    };

    shared.total_packets.fetch_add(1, Ordering::Relaxed);
    shared.total_bytes.fetch_add(total_len, Ordering::Relaxed);

    let key: ConvKey = (proto, local_port, remote_ip, remote_port);

    // Atualiza/cria a conversa. So guardamos pacotes de conversas conhecidas,
    // o que mantem o mapa de pacotes limitado a MAX_CONVS chaves.
    let store = {
        let mut convs = shared.convs.lock().unwrap();
        if let Some(c) = convs.iter_mut().find(|c| c.key() == key) {
            c.packets += 1;
            c.bytes += total_len;
            c.last_ms = ms;
            if c.pid == 0 {
                if let Some((pid, name)) =
                    lookup_pid(&shared.proc_index, proto, local_port, remote_ip, remote_port)
                {
                    c.pid = pid;
                    c.process = name;
                }
            }
            true
        } else if convs.len() < MAX_CONVS {
            let (pid, process) =
                lookup_pid(&shared.proc_index, proto, local_port, remote_ip, remote_port)
                    .unwrap_or((0, String::new()));
            convs.push(Conversation {
                proto,
                local_port,
                remote_ip,
                remote_port,
                pid,
                process,
                packets: 1,
                bytes: total_len,
                last_ms: ms,
            });
            true
        } else {
            false
        }
    };

    if !store {
        return;
    }

    let take = pkt.len().min(MAX_PKT_BYTES);
    let rec = PacketRecord {
        ts_ms: ms,
        outbound,
        proto,
        src,
        dst,
        src_port,
        dst_port,
        total_len: total_len as u16,
        data: pkt[..take].to_vec(),
    };
    let mut packets = shared.packets.lock().unwrap();
    let buf = packets.entry(key).or_default();
    if buf.len() >= MAX_PKTS_PER_CONV {
        buf.pop_front();
    }
    buf.push_back(rec);
}

/// Casa (proto, porta local, IP remoto, porta remota) com o PID dono do socket.
fn lookup_pid(
    idx: &Mutex<ProcIndex>,
    proto: u8,
    lport: u16,
    rip: Ipv4Addr,
    rport: u16,
) -> Option<(u32, String)> {
    let g = idx.lock().unwrap();
    let pid = match proto {
        6 => g
            .tcp
            .get(&(lport, rip, rport))
            .copied()
            .or_else(|| g.tcp_by_lport.get(&lport).copied()),
        17 => g.udp_by_lport.get(&lport).copied(),
        _ => None,
    }?;
    let name = g
        .names
        .get(&pid)
        .cloned()
        .unwrap_or_else(|| format!("pid {pid}"));
    Some((pid, name))
}

/// Le as tabelas TCP/UDP (com dono) do Windows e o snapshot de processos,
/// reconstruindo o indice porta/IP -> PID.
fn refresh_proc_index(idx: &Mutex<ProcIndex>) {
    let mut tcp = HashMap::new();
    let mut tcp_by_lport = HashMap::new();
    let mut udp_by_lport = HashMap::new();

    unsafe {
        let af = AF_INET.0 as u32;

        // --- TCP (com PID dono e tupla completa) ---
        let mut size = 0u32;
        GetExtendedTcpTable(None, &mut size, BOOL(0), af, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let r = GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut size,
                BOOL(0),
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if r == 0 {
                let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let n = table.dwNumEntries as usize;
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
                    n,
                );
                for row in rows {
                    let lport = ntohs(row.dwLocalPort);
                    let rip = dword_ip(row.dwRemoteAddr);
                    let rport = ntohs(row.dwRemotePort);
                    let pid = row.dwOwningPid;
                    tcp_by_lport.entry(lport).or_insert(pid);
                    if !rip.is_unspecified() && rport != 0 {
                        tcp.insert((lport, rip, rport), pid);
                    }
                }
            }
        }

        // --- UDP (sem conexao: so porta local + PID) ---
        let mut size = 0u32;
        GetExtendedUdpTable(None, &mut size, BOOL(0), af, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let r = GetExtendedUdpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut size,
                BOOL(0),
                af,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if r == 0 {
                let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let n = table.dwNumEntries as usize;
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID,
                    n,
                );
                for row in rows {
                    udp_by_lport
                        .entry(ntohs(row.dwLocalPort))
                        .or_insert(row.dwOwningPid);
                }
            }
        }
    }

    let names: HashMap<u32, String> = crate::process::list_processes()
        .into_iter()
        .map(|p| (p.pid, p.name))
        .collect();

    let mut g = idx.lock().unwrap();
    g.tcp = tcp;
    g.tcp_by_lport = tcp_by_lport;
    g.udp_by_lport = udp_by_lport;
    g.names = names;
}

/// Porta nas tabelas MIB vem em network byte order na low word do DWORD.
fn ntohs(dw: u32) -> u16 {
    ((dw & 0xFFFF) as u16).swap_bytes()
}

/// Endereco nas tabelas MIB vem como DWORD em network byte order.
fn dword_ip(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_le_bytes())
}

/// Fecha o socket no fim do escopo.
struct SocketGuard(SOCKET);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = closesocket(self.0);
        }
    }
}

/// Chama WSACleanup no fim do escopo.
struct WsaCleanupGuard;
impl Drop for WsaCleanupGuard {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}
