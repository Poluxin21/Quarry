#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod anticheat;
mod asm_x86;
mod assembler;
mod capture;
mod debugger;
mod disasm;
mod hotkeys;
mod inject;
mod lcu;
mod memory;
mod pointer;
mod process;
mod proxy;
mod scan;
mod table;
mod value;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pointer::{ModuleRanges, PtrPath, PtrScanParams};

use eframe::egui;

use process::{OpenProcessHandle, ProcessInfo};
use scan::{Match, ScanKind, ScanProgress, Scanner};
use value::ValueType;

/// Uma busca em andamento numa thread de fundo.
struct ScanTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<Vec<Match>>,
    is_next: bool,
}

/// Um pointer scan em andamento numa thread de fundo.
struct PtrTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<Vec<PtrPath>>,
}

/// Um AOB scan em andamento numa thread de fundo.
struct AobTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<Vec<u64>>,
}

/// O snapshot inicial da busca de "valor desconhecido" sendo capturado.
struct UnknownTask {
    progress: Arc<ScanProgress>,
    rx: Receiver<scan::Snapshot>,
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Quarry",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

/// Uma entrada salva na "cheat table".
struct SavedEntry {
    address: u64,
    value_type: ValueType,
    desc: String,
    frozen: bool,
    edit_text: String,
    /// se presente, o endereco e resolvido dinamicamente por esta cadeia.
    pointer: Option<PtrPath>,
    /// numero de bytes a ler para tipos string (0 para tipos numericos).
    str_len: usize,
}

impl SavedEntry {
    /// Quantos bytes ler/escrever para exibir o valor desta entrada.
    fn read_len(&self) -> usize {
        if self.value_type.is_string() {
            self.str_len
        } else {
            self.value_type.size()
        }
    }
}

/// Como o endereco de um alvo congelado e obtido a cada tick do freezer.
enum FrozenAddr {
    /// Endereco fixo.
    Fixed(u64),
    /// Resolvido dinamicamente pela cadeia de ponteiros (re-resolve a cada tick,
    /// para acompanhar realocacoes do alvo entre fases/reloads).
    Pointer { base: u64, path: PtrPath },
}

/// Um alvo congelado: como achar o endereco + os bytes a manter.
struct FrozenItem {
    addr: FrozenAddr,
    bytes: Vec<u8>,
}

/// Alvos congelados compartilhados com a thread de freeze.
type FrozenTargets = Arc<Mutex<Vec<FrozenItem>>>;

/// As duas grandes secoes de exploracao do Quarry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Metodos safe que NAO tocam o processo — uso com AC kernel (Vanguard...).
    Kernel,
    /// Acesso direto ao processo (scan/patch/injecao) — sem AC kernel.
    General,
}

/// Modo de exibição do Memory Viewer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MvView {
    Hex,
    Disasm,
}

/// Sub-visões da aba Proxy (espelham o Burp: histórico, intercept, repeater).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyView {
    History,
    Intercept,
    Repeater,
    Rules,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    // --- General Exploring (acessa o processo) ---
    Busca,
    Pointer,
    MemViewer,
    Assembler,
    Injecao,
    // --- Kernel Exploring (safe, sem injecao) ---
    Proxy,
    Capture,
    Lcu,
    KernelOverview,
}

impl Tab {
    fn section(self) -> Section {
        match self {
            Tab::Busca | Tab::Pointer | Tab::MemViewer | Tab::Assembler | Tab::Injecao => {
                Section::General
            }
            Tab::Proxy | Tab::Capture | Tab::Lcu | Tab::KernelOverview => Section::Kernel,
        }
    }
}

const AA_TEMPLATE: &str = "\
[ENABLE]
// 1) ache a instrucao no modulo do jogo (use ?? como curinga)
// aobscanmodule(inject, jogo.exe, 89 83 A4 00 00 00)
// 2) aloque um code cave perto do alvo (saltos rel32 alcancam)
// alloc(newmem, 0x1000, inject)
// registersymbol(inject)
//
// newmem:
//   mov [rbx+0x000000A4], 999   // forca o valor (ou escreva o efeito desejado)
//   jmp return
//
// inject:
//   jmp newmem
//   nop                         // complete o tamanho da instrucao original
// return:

[DISABLE]
// inject:
//   db 89 83 A4 00 00 00        // restaura os bytes originais
// unregistersymbol(inject)
// dealloc(newmem)
";

struct App {
    processes: Vec<ProcessInfo>,
    proc_filter: String,
    show_process_picker: bool,

    attached: Option<Arc<OpenProcessHandle>>,
    attached_name: String,

    value_type: ValueType,
    scan_kind: ScanKind,
    value_text: String,
    /// segundo valor (limite superior) para a comparacao "entre".
    value_text2: String,
    fast_scan: bool,

    scanner: Scanner,
    scan_task: Option<ScanTask>,
    /// snapshot ativo da busca de valor desconhecido (None = busca normal).
    unknown_snapshot: Option<scan::Snapshot>,
    unknown_task: Option<UnknownTask>,
    status: String,

    saved: Vec<SavedEntry>,
    frozen_targets: FrozenTargets,
    /// Sinaliza a thread de freeze atual para encerrar (ao reanexar/trocar de alvo).
    freezer_stop: Option<Arc<AtomicBool>>,
    /// Hotkeys globais (congelar tudo, AA enable/disable).
    hotkeys: hotkeys::HotkeyManager,

    // bases dos modulos no processo (nome -> base), p/ resolver ponteiros
    module_bases: HashMap<String, u64>,

    // --- aba pointer scan ---
    ptr_target_text: String,
    ptr_max_offset_text: String,
    ptr_depth_text: String,
    ptr_align_text: String,
    ptr_results: Vec<PtrPath>,
    ptr_task: Option<PtrTask>,
    /// endereco alvo para validar cadeias apos reabrir o jogo.
    ptr_validate_text: String,

    // --- aba auto assembler ---
    aa_script: String,
    aa_state: assembler::AsmState,
    aa_log: Vec<String>,

    // --- aba memory viewer ---
    mv_addr_text: String,
    mv_view: MvView,
    /// Watch ativo ("o que escreve aqui") — debugger anexado.
    mv_watch: Option<debugger::WatchHandle>,
    mv_watch_access: bool,

    // --- secoes / classificacao de anticheat ---
    section: Section,
    tab: Tab,
    /// classificacao do alvo (None = nada anexado ainda).
    detection: Option<anticheat::Detection>,

    // --- proxy HTTPS (Kernel Exploring) ---
    proxy: Option<proxy::ProxyHandle>,
    proxy_port_text: String,
    proxy_view: ProxyView,
    proxy_filter: String,
    proxy_selected: Option<u64>,
    // intercept: buffers do item em edição
    icpt_id: Option<u64>,
    icpt_headers: String,
    icpt_body: String,
    icpt_follow: bool,
    // repeater
    rep_method: String,
    rep_url: String,
    rep_headers: String,
    rep_body: String,
    rep_rx: Option<proxy::RepeaterRx>,
    rep_busy: bool,
    rep_status: u16,
    rep_resp_headers: String,
    rep_resp_body: String,
    // match & replace
    rules: Vec<proxy::Rule>,

    // --- captura passiva (Kernel Exploring) ---
    capture: Option<capture::CaptureHandle>,
    capture_iface: String,
    capture_filter: String,
    /// Drill-down: processo selecionado (None = lista de processos).
    capture_pid: Option<u32>,
    /// Drill-down: conversa selecionada (None = lista de conversas do processo).
    capture_conv: Option<capture::ConvKey>,
    /// Drill-down: pacote selecionado dentro da conversa.
    capture_pkt: Option<usize>,
    /// Sessões de captura encerradas e guardadas em memória.
    capture_sessions: Vec<CaptureSession>,
    /// Fonte exibida: Some(i) = sessão salva i; None = captura ao vivo.
    capture_session_sel: Option<usize>,
    /// Pacotes fixados no painel de Evidências.
    pinned: Vec<PinnedPacket>,
    /// Evidência selecionada para detalhe.
    pinned_sel: Option<usize>,

    // --- API local do client / LCU (Kernel Exploring) ---
    lcu_conn: Option<lcu::LcuConn>,
    lcu_method: String,
    lcu_path: String,
    lcu_body: String,
    lcu_rx: Option<lcu::LcuRx>,
    lcu_busy: bool,
    lcu_status: u16,
    lcu_resp: String,

    // --- aba de injecao ---
    modules: Vec<inject::ModuleInfo>,
    module_filter: String,
    aob_text: String,
    aob_results: Vec<u64>,
    aob_task: Option<AobTask>,
    dll_path: String,
    patch_addr_text: String,
    patch_bytes_text: String,
    nop_addr_text: String,
    nop_len_text: String,
}

impl Default for App {
    fn default() -> Self {
        let frozen_targets: FrozenTargets = Arc::new(Mutex::new(Vec::new()));
        Self {
            processes: Vec::new(),
            proc_filter: String::new(),
            show_process_picker: false,
            attached: None,
            attached_name: String::new(),
            value_type: ValueType::I32,
            scan_kind: ScanKind::Exact,
            value_text: String::new(),
            value_text2: String::new(),
            fast_scan: true,
            scanner: Scanner::new(ValueType::I32),
            scan_task: None,
            unknown_snapshot: None,
            unknown_task: None,
            status: "Nenhum processo anexado.".into(),
            saved: Vec::new(),
            frozen_targets,
            freezer_stop: None,
            hotkeys: hotkeys::HotkeyManager::start(),
            module_bases: HashMap::new(),
            ptr_target_text: String::new(),
            ptr_max_offset_text: "2048".into(),
            ptr_depth_text: "4".into(),
            ptr_align_text: "4".into(),
            ptr_results: Vec::new(),
            ptr_task: None,
            ptr_validate_text: String::new(),
            aa_script: AA_TEMPLATE.to_string(),
            aa_state: assembler::AsmState::new(),
            aa_log: Vec::new(),
            mv_addr_text: String::new(),
            mv_view: MvView::Hex,
            mv_watch: None,
            mv_watch_access: false,
            section: Section::General,
            tab: Tab::Busca,
            detection: None,
            proxy: None,
            proxy_port_text: "8080".into(),
            proxy_view: ProxyView::History,
            proxy_filter: String::new(),
            proxy_selected: None,
            icpt_id: None,
            icpt_headers: String::new(),
            icpt_body: String::new(),
            icpt_follow: false,
            rep_method: "GET".into(),
            rep_url: String::new(),
            rep_headers: String::new(),
            rep_body: String::new(),
            rep_rx: None,
            rep_busy: false,
            rep_status: 0,
            rep_resp_headers: String::new(),
            rep_resp_body: String::new(),
            rules: Vec::new(),
            capture: None,
            capture_iface: capture::primary_ipv4()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            capture_filter: String::new(),
            capture_pid: None,
            capture_conv: None,
            capture_pkt: None,
            capture_sessions: Vec::new(),
            capture_session_sel: None,
            pinned: Vec::new(),
            pinned_sel: None,
            lcu_conn: None,
            lcu_method: "GET".into(),
            lcu_path: "/lol-summoner/v1/current-summoner".into(),
            lcu_body: String::new(),
            lcu_rx: None,
            lcu_busy: false,
            lcu_status: 0,
            lcu_resp: String::new(),
            modules: Vec::new(),
            module_filter: String::new(),
            aob_text: String::new(),
            aob_results: Vec::new(),
            aob_task: None,
            dll_path: String::new(),
            patch_addr_text: String::new(),
            patch_bytes_text: String::new(),
            nop_addr_text: String::new(),
            nop_len_text: "1".into(),
        }
    }
}

fn parse_addr(text: &str) -> Option<u64> {
    let t = text.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

/// Formata um numero de bytes em B/KB/MB/GB.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Extrai o payload L4 (depois dos cabeçalhos IP + TCP/UDP) de um pacote bruto.
fn capture_l4_payload(rec: &capture::PacketRecord) -> &[u8] {
    let d = &rec.data;
    if d.len() < 20 {
        return &[];
    }
    let ihl = ((d[0] & 0x0f) as usize) * 4;
    if d.len() < ihl {
        return &[];
    }
    match rec.proto {
        6 => {
            // TCP: data offset (em palavras de 32 bits) está no nibble alto do byte 12
            if d.len() < ihl + 20 {
                return &[];
            }
            let data_off = ((d[ihl + 12] >> 4) as usize) * 4;
            let start = ihl + data_off;
            if d.len() < start {
                &[]
            } else {
                &d[start..]
            }
        }
        17 => {
            let start = ihl + 8; // cabeçalho UDP é fixo (8 bytes)
            if d.len() < start {
                &[]
            } else {
                &d[start..]
            }
        }
        _ => &d[ihl..],
    }
}

/// Se o payload parecer uma requisição/resposta HTTP em texto puro, devolve a
/// primeira linha (request line ou status line).
fn http_first_line(payload: &[u8]) -> Option<String> {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE", b"PATCH ", b"OPTIONS", b"TRACE ",
        b"HTTP/",
    ];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    let end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len().min(120));
    let line = String::from_utf8_lossy(&payload[..end]).trim().to_string();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

/// Traduz bytes brutos em texto legível: mantém ASCII imprimível, tabs e quebras
/// de linha; troca os demais por '.'. Útil para HTTP/JSON em texto puro (em
/// tráfego cifrado vira majoritariamente pontos, como esperado).
fn readable_text(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'\n' => s.push('\n'),
            b'\t' => s.push('\t'),
            b'\r' => {} // descarta CR para não poluir as linhas
            0x20..=0x7e => s.push(b as char),
            _ => s.push('.'),
        }
    }
    s
}

/// Monta um hex dump estilo `xxd`: offset, 16 bytes em hex e a coluna ASCII.
fn hex_dump(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 4);
    for (i, chunk) in data.chunks(16).enumerate() {
        let off = i * 16;
        let mut hex = String::new();
        let mut asc = String::new();
        for (j, b) in chunk.iter().enumerate() {
            hex.push_str(&format!("{b:02x} "));
            if j == 7 {
                hex.push(' ');
            }
            asc.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        // alinha a coluna ASCII quando a última linha tem menos de 16 bytes
        for j in chunk.len()..16 {
            hex.push_str("   ");
            if j == 7 {
                hex.push(' ');
            }
        }
        out.push_str(&format!("{off:08x}  {hex} |{asc}|\n"));
    }
    out
}

/// Hex dump com a coluna de endereço absoluta (Memory Viewer).
fn hex_dump_at(base: u64, data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 4);
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        let mut hex = String::new();
        let mut asc = String::new();
        for (j, b) in chunk.iter().enumerate() {
            hex.push_str(&format!("{b:02X} "));
            if j == 7 {
                hex.push(' ');
            }
            asc.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        for j in chunk.len()..16 {
            hex.push_str("   ");
            if j == 7 {
                hex.push(' ');
            }
        }
        out.push_str(&format!("{addr:016X}  {hex} |{asc}|\n"));
    }
    out
}

/// Uma sessão de captura já encerrada e guardada em memória, para revisão.
struct CaptureSession {
    name: String,
    iface: String,
    convs: Vec<capture::Conversation>,
    packets: HashMap<capture::ConvKey, Vec<capture::PacketRecord>>,
    total_packets: u64,
    total_bytes: u64,
}

/// Um pacote fixado no painel de Evidências (arrastado ou fixado pelo usuário).
#[derive(Clone)]
struct PinnedPacket {
    label: String,
    rec: capture::PacketRecord,
}

/// Constrói uma evidência (rótulo + cópia do pacote) a partir de um pacote.
fn pinned_from(p: &capture::PacketRecord) -> PinnedPacket {
    let arrow = if p.outbound { "▲" } else { "▼" };
    let label = format!(
        "{arrow} {} {}:{}→{}:{} · {:.3}s · {}B",
        p.proto_name(),
        p.src,
        p.src_port,
        p.dst,
        p.dst_port,
        p.ts_ms as f64 / 1000.0,
        p.total_len
    );
    PinnedPacket {
        label,
        rec: p.clone(),
    }
}

/// Tira um retrato do estado vivo da captura e o congela numa [`CaptureSession`].
fn snapshot_session(
    shared: &capture::CaptureShared,
    iface: &str,
    name: String,
) -> CaptureSession {
    use std::sync::atomic::Ordering;
    let convs = shared.convs.lock().unwrap().clone();
    let packets = shared
        .packets
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (*k, v.iter().cloned().collect()))
        .collect();
    CaptureSession {
        name,
        iface: iface.to_string(),
        convs,
        packets,
        total_packets: shared.total_packets.load(Ordering::Relaxed),
        total_bytes: shared.total_bytes.load(Ordering::Relaxed),
    }
}

/// Escreve pacotes num arquivo .pcap clássico (LINKTYPE_RAW = IP cru).
fn write_pcap(path: &std::path::Path, packets: &[capture::PacketRecord]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    // Cabeçalho global (24 bytes), little-endian.
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    f.write_all(&2u16.to_le_bytes())?; // versão major
    f.write_all(&4u16.to_le_bytes())?; // versão minor
    f.write_all(&0i32.to_le_bytes())?; // thiszone (UTC)
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&101u32.to_le_bytes())?; // network = LINKTYPE_RAW
    for p in packets {
        let ts_sec = (p.ts_ms / 1000) as u32;
        let ts_usec = ((p.ts_ms % 1000) * 1000) as u32;
        f.write_all(&ts_sec.to_le_bytes())?;
        f.write_all(&ts_usec.to_le_bytes())?;
        f.write_all(&(p.data.len() as u32).to_le_bytes())?; // incl_len (capturado)
        f.write_all(&(p.total_len as u32).to_le_bytes())?; // orig_len (real)
        f.write_all(&p.data)?;
    }
    f.flush()
}

impl App {
    fn attach(&mut self, pid: u32, name: String) {
        match OpenProcessHandle::open(pid) {
            Ok(h) => {
                let handle = Arc::new(h);
                self.spawn_freezer(handle.clone());
                self.attached = Some(handle);
                self.attached_name = format!("{name} (pid {pid})");
                self.scanner.reset();
                self.refresh_module_bases(pid);
                self.classify(pid, &name);
                self.status = format!("Anexado em {name}.");
            }
            Err(e) => {
                self.status = format!(
                    "Falha ao anexar (pid {pid}): {e}. Rode o Quarry como Administrador."
                );
            }
        }
    }

    /// Classifica o alvo (AC kernel / user-mode / sem protecao) e roteia
    /// para a secao correta. Com AC kernel, forca a secao Kernel Exploring.
    fn classify(&mut self, pid: u32, exe_name: &str) {
        let modules = inject::list_modules(pid);
        let det = anticheat::detect(exe_name, &modules);
        if det.protection.blocks_injection() {
            // alvo protegido por AC kernel: empurra para a aba safe.
            self.section = Section::Kernel;
            self.tab = Tab::KernelOverview;
        } else {
            self.section = Section::General;
            self.tab = Tab::Busca;
        }
        self.detection = Some(det);
    }

    /// True quando a injecao/patch deve ficar bloqueada (AC kernel detectado).
    fn injection_blocked(&self) -> bool {
        self.detection
            .as_ref()
            .is_some_and(|d| d.protection.blocks_injection())
    }

    /// Recolhe a resposta do Repeater quando pronta (sem bloquear).
    fn poll_repeater(&mut self) {
        let Some(rx) = &mut self.rep_rx else {
            return;
        };
        match proxy::poll_repeater(rx) {
            proxy::RepeaterPoll::Pending => {}
            proxy::RepeaterPoll::Done(r) => {
                self.rep_status = r.status;
                self.rep_resp_headers = r.headers;
                self.rep_resp_body = r.body;
                self.rep_busy = false;
                self.rep_rx = None;
            }
            proxy::RepeaterPoll::Closed => {
                self.rep_busy = false;
                self.rep_rx = None;
            }
        }
    }

    fn poll_lcu(&mut self) {
        let Some(rx) = &mut self.lcu_rx else {
            return;
        };
        match lcu::poll(rx) {
            lcu::LcuPoll::Pending => {}
            lcu::LcuPoll::Done(Ok(r)) => {
                self.lcu_status = r.status;
                self.lcu_resp = r.body;
                self.lcu_busy = false;
                self.lcu_rx = None;
            }
            lcu::LcuPoll::Done(Err(e)) => {
                self.lcu_status = 0;
                self.lcu_resp = e;
                self.lcu_busy = false;
                self.lcu_rx = None;
            }
            lcu::LcuPoll::Closed => {
                self.lcu_busy = false;
                self.lcu_rx = None;
            }
        }
    }

    /// Thread que reescreve os valores congelados periodicamente. Encerra a thread
    /// anterior (se houver) para nao deixar freezers orfaos escrevendo no alvo
    /// antigo ao reanexar.
    fn spawn_freezer(&mut self, handle: Arc<OpenProcessHandle>) {
        if let Some(stop) = self.freezer_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.freezer_stop = Some(stop.clone());
        let targets = self.frozen_targets.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                {
                    let list = targets.lock().unwrap();
                    for item in list.iter() {
                        let addr = match &item.addr {
                            FrozenAddr::Fixed(a) => Some(*a),
                            FrozenAddr::Pointer { base, path } => {
                                pointer::resolve(handle.raw(), *base, path)
                            }
                        };
                        if let Some(a) = addr {
                            memory::write_bytes(handle.raw(), a, &item.bytes);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
    }

    fn rebuild_frozen_targets(&self) {
        let mut list = self.frozen_targets.lock().unwrap();
        list.clear();
        let Some(h) = &self.attached else {
            return;
        };
        for e in self.saved.iter().filter(|e| e.frozen) {
            // bytes a manter: o valor digitado ou, na ausencia, o valor atual.
            let bytes = if let Some(b) = e.value_type.parse_to_bytes(&e.edit_text) {
                b
            } else {
                let Some(addr) = self.entry_address(e) else {
                    continue;
                };
                match memory::read_bytes(h.raw(), addr, e.read_len()) {
                    Some(b) => b,
                    None => continue,
                }
            };
            let addr = match &e.pointer {
                None => FrozenAddr::Fixed(e.address),
                Some(path) => {
                    let Some(base) = self.module_bases.get(&path.module).copied() else {
                        continue;
                    };
                    FrozenAddr::Pointer { base, path: path.clone() }
                }
            };
            list.push(FrozenItem { addr, bytes });
        }
    }

    /// Abre um diálogo para salvar a cheat table atual em um arquivo `.qct`.
    fn save_table_dialog(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Quarry Cheat Table", &["qct"])
            .set_file_name("tabela.qct")
            .save_file()
        else {
            return;
        };
        let entries: Vec<table::TableEntry> = self
            .saved
            .iter()
            .map(|e| table::TableEntry {
                address: e.address,
                value_type: e.value_type,
                desc: e.desc.clone(),
                frozen: e.frozen,
                edit_text: e.edit_text.clone(),
                pointer: e.pointer.clone(),
                str_len: e.str_len,
            })
            .collect();
        let file = table::TableFile::new(
            self.attached_name.clone(),
            self.aa_script.clone(),
            entries,
        );
        match table::save(&path, &file) {
            Ok(()) => self.status = format!("Tabela salva em {}.", path.display()),
            Err(e) => self.status = format!("Falha ao salvar tabela: {e}"),
        }
    }

    /// Abre um diálogo para carregar uma cheat table de um arquivo `.qct`.
    fn load_table_dialog(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Quarry Cheat Table", &["qct"])
            .pick_file()
        else {
            return;
        };
        let file = match table::load(&path) {
            Ok(f) => f,
            Err(e) => {
                self.status = format!("Falha ao carregar tabela: {e}");
                return;
            }
        };
        self.saved = file
            .entries
            .into_iter()
            .map(|e| SavedEntry {
                address: e.address,
                value_type: e.value_type,
                desc: e.desc,
                frozen: e.frozen,
                edit_text: e.edit_text,
                pointer: e.pointer,
                str_len: e.str_len,
            })
            .collect();
        if !file.aa_script.trim().is_empty() {
            self.aa_script = file.aa_script;
        }
        self.rebuild_frozen_targets();
        self.status = format!(
            "Tabela carregada de {} ({} entradas).",
            path.display(),
            self.saved.len()
        );
    }

    /// Monta os parametros de comparacao a partir da UI. None se o valor digitado
    /// for invalido para o tipo. Para comparacoes relativas nao exige valor.
    fn build_cmp(&self) -> Option<scan::ScanCmp> {
        if !self.scan_kind.needs_value() {
            return Some(scan::ScanCmp::relative(self.scan_kind));
        }
        let vt = self.value_type;
        let b1 = vt.parse_to_bytes(&self.value_text)?;
        let t1_i = vt.read_i128(&b1).unwrap_or(0);
        let t1_f = vt.read_f64(&b1).unwrap_or(0.0);
        let (t2_i, t2_f) = if self.scan_kind.needs_two() {
            let b2 = vt.parse_to_bytes(&self.value_text2)?;
            (vt.read_i128(&b2).unwrap_or(0), vt.read_f64(&b2).unwrap_or(0.0))
        } else {
            (0, 0.0)
        };
        Some(scan::ScanCmp {
            kind: self.scan_kind,
            t1_i,
            t2_i,
            t1_f,
            t2_f,
        })
    }

    fn do_first_scan(&mut self) {
        if self.scan_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };

        if self.value_type.is_string() {
            self.start_string_scan(h, false);
            return;
        }

        if !self.scan_kind.needs_value() {
            self.status =
                "Comparacoes relativas (mudou/aumentou/...) so valem no Next Scan. Use 'valor exato', \
                 'maior que' ou 'menor que' no First Scan."
                    .into();
            return;
        }
        let Some(cmp) = self.build_cmp() else {
            self.status = "Valor invalido para o tipo selecionado.".into();
            return;
        };
        self.scanner = Scanner::new(self.value_type);
        self.scanner.fast_scan = self.fast_scan;

        let regions = memory::enumerate_regions(h.raw());
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let value_type = self.value_type;
        let fast_scan = self.fast_scan;
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result =
                scan::first_scan_job(h.raw(), &regions, value_type, fast_scan, cmp, &prog);
            let _ = tx.send(result);
        });

        self.scan_task = Some(ScanTask {
            progress,
            rx,
            is_next: false,
        });
        self.status = "First scan em andamento...".into();
    }

    /// First scan de "valor desconhecido": captura um snapshot das regioes
    /// gravaveis numa thread de fundo.
    fn do_unknown_first(&mut self) {
        if self.scan_task.is_some() || self.unknown_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        if self.value_type.is_string() {
            self.status = "Valor desconhecido não se aplica a strings.".into();
            return;
        }
        self.scanner = Scanner::new(self.value_type);
        self.scanner.fast_scan = self.fast_scan;
        self.unknown_snapshot = None;

        let regions = memory::enumerate_regions(h.raw());
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();
        let prog = progress.clone();
        std::thread::spawn(move || {
            let snap = scan::unknown_first_job(h.raw(), &regions, &prog);
            let _ = tx.send(snap);
        });
        self.unknown_task = Some(UnknownTask { progress, rx });
        self.status = "Capturando snapshot (valor desconhecido)…".into();
    }

    fn poll_unknown_task(&mut self) {
        let Some(task) = &self.unknown_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(snap) => {
                let n = snap.regions.len();
                self.unknown_snapshot = Some(snap);
                self.scanner.matches.clear();
                self.scanner.has_scanned = true;
                self.unknown_task = None;
                self.status = format!(
                    "Snapshot capturado ({n} regiões). Mude o valor no jogo e use Next Scan \
                     (mudou/aumentou/diminuiu…)."
                );
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "Snapshot interrompido.".into();
                self.unknown_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    /// Dispara um scan de string (first ou next) numa thread de fundo.
    fn start_string_scan(&mut self, h: Arc<OpenProcessHandle>, is_next: bool) {
        let Some(pattern) = self.value_type.parse_to_bytes(&self.value_text) else {
            self.status = "Texto invalido.".into();
            return;
        };
        if pattern.is_empty() {
            self.status = "Digite um texto para procurar.".into();
            return;
        }

        let (tx, rx) = std::sync::mpsc::channel();
        if is_next {
            let current = std::mem::take(&mut self.scanner.matches);
            let progress = ScanProgress::new(current.len());
            let prog = progress.clone();
            std::thread::spawn(move || {
                let result = scan::next_scan_string_job(h.raw(), current, &pattern, &prog);
                let _ = tx.send(result);
            });
            self.scan_task = Some(ScanTask { progress, rx, is_next: true });
            self.status = "Next scan (texto) em andamento...".into();
        } else {
            self.scanner = Scanner::new(self.value_type);
            let regions = memory::enumerate_regions(h.raw());
            let progress = ScanProgress::new(regions.len());
            let prog = progress.clone();
            std::thread::spawn(move || {
                let result = scan::first_scan_string_job(h.raw(), &regions, &pattern, &prog);
                let _ = tx.send(result);
            });
            self.scan_task = Some(ScanTask { progress, rx, is_next: false });
            self.status = "First scan (texto) em andamento...".into();
        }
    }

    fn do_next_scan(&mut self) {
        if self.scan_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            return;
        };
        if !self.scanner.has_scanned {
            self.status = "Faca um First Scan antes.".into();
            return;
        }

        if self.value_type.is_string() {
            self.start_string_scan(h, true);
            return;
        }

        // primeiro next scan apos um snapshot de valor desconhecido.
        if let Some(snap) = self.unknown_snapshot.take() {
            let Some(cmp) = self.build_cmp() else {
                self.status = "Valor invalido.".into();
                self.unknown_snapshot = Some(snap);
                return;
            };
            let progress = ScanProgress::new(snap.regions.len().max(1));
            let (tx, rx) = std::sync::mpsc::channel();
            let value_type = self.value_type;
            let fast_scan = self.fast_scan;
            let prog = progress.clone();
            std::thread::spawn(move || {
                let result =
                    scan::unknown_next_job(h.raw(), &snap, value_type, fast_scan, cmp, &prog);
                let _ = tx.send(result);
            });
            self.scan_task = Some(ScanTask { progress, rx, is_next: true });
            self.status = "Next scan (valor desconhecido) em andamento…".into();
            return;
        }

        let Some(cmp) = self.build_cmp() else {
            self.status = "Valor invalido.".into();
            return;
        };

        let current = std::mem::take(&mut self.scanner.matches);
        let progress = ScanProgress::new(current.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let value_type = self.value_type;
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result = scan::next_scan_job(h.raw(), current, value_type, cmp, &prog);
            let _ = tx.send(result);
        });

        self.scan_task = Some(ScanTask {
            progress,
            rx,
            is_next: true,
        });
        self.status = "Next scan em andamento...".into();
    }

    /// Mantem so as cadeias que ainda resolvem para `target` (validacao entre runs).
    fn validate_chains(&mut self, target: u64) {
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe o processo (reaberto) antes de validar.".into();
            return;
        };
        let bases = self.module_bases.clone();
        let before = self.ptr_results.len();
        self.ptr_results.retain(|path| {
            bases
                .get(&path.module)
                .and_then(|b| pointer::resolve(h.raw(), *b, path))
                == Some(target)
        });
        self.status = format!(
            "Validação: {} de {before} cadeias resolvem para {target:016X}.",
            self.ptr_results.len()
        );
    }

    fn refresh_module_bases(&mut self, pid: u32) {
        self.module_bases.clear();
        for m in inject::list_modules(pid) {
            self.module_bases.entry(m.name).or_insert(m.base);
        }
    }

    /// Endereco efetivo de uma entrada: fixo, ou resolvido pela cadeia de ponteiros.
    fn entry_address(&self, e: &SavedEntry) -> Option<u64> {
        let h = self.attached.as_ref()?;
        match &e.pointer {
            None => Some(e.address),
            Some(path) => {
                let base = *self.module_bases.get(&path.module)?;
                pointer::resolve(h.raw(), base, path)
            }
        }
    }

    fn do_pointer_scan(&mut self) {
        if self.ptr_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let Some(target) = parse_addr(&self.ptr_target_text) else {
            self.status = "Endereco alvo invalido (use hex).".into();
            return;
        };
        let max_offset = self.ptr_max_offset_text.trim().parse::<u64>().unwrap_or(2048);
        let max_depth = self.ptr_depth_text.trim().parse::<usize>().unwrap_or(4).clamp(1, 8);
        let alignment = self.ptr_align_text.trim().parse::<usize>().unwrap_or(4).max(1);

        let regions = memory::enumerate_regions(h.raw());
        let modules = ModuleRanges::from(&inject::list_modules(h.pid));
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();

        let params = PtrScanParams {
            target,
            max_offset,
            max_depth,
            alignment,
            max_results: 5000,
        };
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result = pointer::pointer_scan(h.raw(), &regions, &modules, params, &prog);
            let _ = tx.send(result);
        });

        self.ptr_task = Some(PtrTask { progress, rx });
        self.status = "Pointer scan em andamento...".into();
    }

    fn poll_ptr_task(&mut self) {
        let Some(task) = &self.ptr_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(result) => {
                self.status = format!("Pointer scan: {} cadeias encontradas.", result.len());
                self.ptr_results = result;
                self.ptr_task = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "Pointer scan interrompido.".into();
                self.ptr_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    /// Processa hotkeys globais disparadas desde o ultimo frame.
    fn poll_hotkeys(&mut self) {
        for id in self.hotkeys.poll() {
            match id {
                hotkeys::HK_FREEZE_ALL => {
                    for e in &mut self.saved {
                        e.frozen = true;
                    }
                    self.rebuild_frozen_targets();
                    self.status = "Hotkey: tudo congelado.".into();
                }
                hotkeys::HK_UNFREEZE_ALL => {
                    for e in &mut self.saved {
                        e.frozen = false;
                    }
                    self.rebuild_frozen_targets();
                    self.status = "Hotkey: tudo descongelado.".into();
                }
                hotkeys::HK_AA_ENABLE => {
                    if !self.injection_blocked() {
                        self.run_assembler(assembler::Section::Enable);
                    }
                }
                hotkeys::HK_AA_DISABLE => {
                    if !self.injection_blocked() {
                        self.run_assembler(assembler::Section::Disable);
                    }
                }
                _ => {}
            }
        }
    }

    fn poll_aob_task(&mut self) {
        let Some(task) = &self.aob_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(result) => {
                self.status = format!("AOB: {} ocorrências.", result.len());
                self.aob_results = result;
                self.aob_task = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "AOB scan interrompido.".into();
                self.aob_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    /// Dispara um AOB scan numa thread de fundo.
    fn do_aob_scan(&mut self) {
        if self.aob_task.is_some() {
            return;
        }
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let Some(pat) = inject::parse_aob(&self.aob_text) else {
            self.status = "Padrão AOB inválido.".into();
            return;
        };
        let regions = memory::enumerate_regions(h.raw());
        let progress = ScanProgress::new(regions.len());
        let (tx, rx) = std::sync::mpsc::channel();
        let prog = progress.clone();
        std::thread::spawn(move || {
            let result = inject::aob_scan_job(h.raw(), &regions, &pat, 200, &prog);
            let _ = tx.send(result);
        });
        self.aob_task = Some(AobTask { progress, rx });
        self.status = "AOB scan em andamento...".into();
    }

    /// Verifica se a busca em andamento terminou e recolhe o resultado.
    fn poll_scan_task(&mut self) {
        let Some(task) = &self.scan_task else {
            return;
        };
        match task.rx.try_recv() {
            Ok(result) => {
                let is_next = task.is_next;
                self.scanner.matches = result;
                self.scanner.has_scanned = true;
                self.status = format!(
                    "{}: {} resultados.",
                    if is_next { "Next scan" } else { "First scan" },
                    self.scanner.matches.len()
                );
                self.scan_task = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "Busca interrompida (thread encerrou).".into();
                self.scan_task = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_hotkeys();
        self.poll_scan_task();
        self.poll_unknown_task();
        self.poll_ptr_task();
        self.poll_aob_task();
        self.poll_repeater();
        self.poll_lcu();
        // repinta rapido durante a busca; medio com proxy/captura/lcu ativos; devagar ocioso
        if self.scan_task.is_some()
            || self.ptr_task.is_some()
            || self.aob_task.is_some()
            || self.unknown_task.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(60));
        } else if self.proxy.is_some()
            || self.capture.is_some()
            || self.lcu_busy
        {
            ctx.request_repaint_after(Duration::from_millis(150));
        } else {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        if self.show_process_picker {
            self.process_picker(ctx);
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Selecionar processo").clicked() {
                    self.processes = process::list_processes();
                    self.show_process_picker = true;
                }
                ui.separator();
                if self.attached.is_some() {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &self.attached_name);
                } else {
                    ui.colored_label(egui::Color32::GRAY, "(sem processo)");
                }
                ui.separator();
                self.protection_badge(ui);
            });

            ui.horizontal(|ui| {
                // Seletor de secao. Mudar de secao ajusta a aba ativa.
                if ui
                    .selectable_label(self.section == Section::Kernel, "🛡 Kernel Exploring")
                    .clicked()
                {
                    self.section = Section::Kernel;
                    self.tab = Tab::KernelOverview;
                }
                let general_resp = ui.selectable_label(
                    self.section == Section::General,
                    "🔧 General Exploring",
                );
                if general_resp.clicked() {
                    self.section = Section::General;
                    if self.tab.section() != Section::General {
                        self.tab = Tab::Busca;
                    }
                }
                if self.injection_blocked() {
                    general_resp.on_hover_text(
                        "Anticheat kernel detectado — acesso direto ao processo bloqueado. \
                         Use Kernel Exploring.",
                    );
                }
            });

            ui.separator();
            ui.horizontal(|ui| match self.section {
                Section::General => {
                    ui.selectable_value(&mut self.tab, Tab::Busca, "Busca");
                    ui.selectable_value(&mut self.tab, Tab::Pointer, "Pointer Scan");
                    ui.selectable_value(&mut self.tab, Tab::MemViewer, "Memory Viewer");
                    ui.selectable_value(&mut self.tab, Tab::Assembler, "Auto Assembler");
                    ui.selectable_value(&mut self.tab, Tab::Injecao, "Injeção");
                }
                Section::Kernel => {
                    ui.selectable_value(&mut self.tab, Tab::Proxy, "Proxy HTTPS");
                    ui.selectable_value(&mut self.tab, Tab::Capture, "Captura passiva");
                    ui.selectable_value(&mut self.tab, Tab::KernelOverview, "Visão geral");
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        // Painel direito: cheat table só quando se está mexendo com memória
        // (General Exploring); na aba Captura ele vira o painel de Evidências.
        if self.section == Section::General {
            egui::SidePanel::right("table")
                .resizable(true)
                .default_width(420.0)
                .show(ctx, |ui| {
                    self.saved_table(ui);
                });
        } else if self.tab == Tab::Capture {
            egui::SidePanel::right("evidence")
                .resizable(true)
                .default_width(360.0)
                .show(ctx, |ui| {
                    self.evidence_panel(ui);
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Busca => self.scan_panel(ui),
            Tab::Pointer => self.pointer_panel(ui),
            Tab::MemViewer => self.mem_viewer_panel(ui),
            Tab::Assembler => self.assembler_panel(ui),
            Tab::Injecao => self.inject_panel(ui),
            Tab::Proxy => self.proxy_panel(ui),
            Tab::Capture => self.capture_panel(ui),
            Tab::Lcu => self.lcu_panel(ui),
            Tab::KernelOverview => self.kernel_panel(ui),
        });
    }
}

impl App {
    fn process_picker(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut chosen: Option<(u32, String)> = None;
        egui::Window::new("Selecionar processo")
            .open(&mut open)
            .resizable(true)
            .default_size([400.0, 500.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Filtro:");
                    ui.text_edit_singleline(&mut self.proc_filter);
                    if ui.button("Atualizar").clicked() {
                        self.processes = process::list_processes();
                    }
                });
                ui.separator();
                let filter = self.proc_filter.to_lowercase();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for p in &self.processes {
                        if !filter.is_empty() && !p.name.to_lowercase().contains(&filter) {
                            continue;
                        }
                        if ui
                            .button(format!("{}  —  pid {}", p.name, p.pid))
                            .clicked()
                        {
                            chosen = Some((p.pid, p.name.clone()));
                        }
                    }
                });
            });
        if let Some((pid, name)) = chosen {
            self.attach(pid, name);
            self.show_process_picker = false;
        }
        if !open {
            self.show_process_picker = false;
        }
    }

    fn scan_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Busca de valores");
        ui.add_space(4.0);

        let is_string = self.value_type.is_string();
        if is_string {
            // strings so suportam busca por texto exato
            self.scan_kind = ScanKind::Exact;
        }

        egui::Grid::new("scan_controls")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Tipo:");
                egui::ComboBox::from_id_source("vt")
                    .selected_text(self.value_type.label())
                    .show_ui(ui, |ui| {
                        for vt in ValueType::ALL {
                            ui.selectable_value(&mut self.value_type, vt, vt.label());
                        }
                    });
                ui.end_row();

                ui.label("Comparacao:");
                if is_string {
                    ui.add_enabled(false, egui::Button::new("Texto exato"));
                } else {
                    egui::ComboBox::from_id_source("sk")
                        .selected_text(scan_kind_label(self.scan_kind))
                        .show_ui(ui, |ui| {
                            use ScanKind::*;
                            for k in [
                                Exact, BiggerThan, SmallerThan, Between, Changed, Unchanged,
                                Increased, Decreased,
                            ] {
                                ui.selectable_value(&mut self.scan_kind, k, scan_kind_label(k));
                            }
                        });
                }
                ui.end_row();

                ui.label(if is_string {
                    "Texto:"
                } else if self.scan_kind.needs_two() {
                    "De:"
                } else {
                    "Valor:"
                });
                ui.add_enabled(
                    is_string || self.scan_kind.needs_value(),
                    egui::TextEdit::singleline(&mut self.value_text),
                );
                ui.end_row();

                if !is_string && self.scan_kind.needs_two() {
                    ui.label("Até:");
                    ui.text_edit_singleline(&mut self.value_text2);
                    ui.end_row();
                }
            });

        ui.add_enabled_ui(!is_string, |ui| {
            ui.checkbox(&mut self.fast_scan, "Fast scan (alinhado — mais rapido)");
        });

        ui.add_space(6.0);
        let scanning = self.scan_task.is_some() || self.unknown_task.is_some();
        ui.horizontal(|ui| {
            let enabled = self.attached.is_some() && !scanning;
            if ui
                .add_enabled(enabled, egui::Button::new("First Scan"))
                .clicked()
            {
                self.do_first_scan();
            }
            if ui
                .add_enabled(
                    enabled && self.scanner.has_scanned,
                    egui::Button::new("Next Scan"),
                )
                .clicked()
            {
                self.do_next_scan();
            }
            if ui
                .add_enabled(!scanning, egui::Button::new("Nova busca"))
                .clicked()
            {
                self.scanner.reset();
                self.unknown_snapshot = None;
                self.status = "Busca limpa.".into();
            }
        });
        ui.add_enabled_ui(!is_string, |ui| {
            if ui
                .add_enabled(
                    self.attached.is_some() && !scanning,
                    egui::Button::new("First Scan — valor inicial desconhecido"),
                )
                .on_hover_text(
                    "Captura um snapshot da memória gravável. Depois mude o valor no jogo e \
                     use Next Scan com mudou/aumentou/diminuiu para achá-lo sem saber o número.",
                )
                .clicked()
            {
                self.do_unknown_first();
            }
            if self.unknown_snapshot.is_some() {
                ui.weak("● snapshot ativo — use Next Scan (mudou/aumentou/diminuiu/igual a …).");
            }
        });

        if let Some(task) = &self.scan_task {
            let frac = task.progress.fraction();
            ui.add(
                egui::ProgressBar::new(frac)
                    .show_percentage()
                    .text(format!("{} encontrados", task.progress.matches_count())),
            );
            if ui.button("Cancelar").clicked() {
                task.progress.request_cancel();
            }
        } else if let Some(task) = &self.unknown_task {
            let frac = task.progress.fraction();
            ui.add(
                egui::ProgressBar::new(frac)
                    .show_percentage()
                    .text(format!("{} regiões capturadas", task.progress.matches_count())),
            );
            if ui.button("Cancelar").clicked() {
                task.progress.request_cancel();
            }
        }

        ui.separator();
        let total = self.scanner.matches.len();
        ui.label(format!("Resultados: {total} (mostrando ate 1000)"));

        // comprimento de leitura: fixo para numeros, tamanho do texto para strings
        let read_len = if is_string {
            self.value_type
                .parse_to_bytes(&self.value_text)
                .map(|b| b.len())
                .unwrap_or(0)
        } else {
            self.value_type.size()
        };

        let handle = self.attached.clone();
        let mut add_addr: Option<(u64, ValueType, usize)> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("results")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Endereco");
                    ui.strong("Valor atual");
                    ui.strong("");
                    ui.end_row();
                    for m in self.scanner.matches.iter().take(1000) {
                        ui.monospace(format!("{:016X}", m.address));
                        let cur = if read_len == 0 {
                            "?".into()
                        } else {
                            handle
                                .as_ref()
                                .and_then(|h| memory::read_bytes(h.raw(), m.address, read_len))
                                .map(|b| self.value_type.format(&b))
                                .unwrap_or_else(|| "?".into())
                        };
                        ui.monospace(cur);
                        if ui.small_button("+ tabela").clicked() {
                            add_addr = Some((m.address, self.value_type, read_len));
                        }
                        ui.end_row();
                    }
                });
        });

        if let Some((address, vt, str_len)) = add_addr {
            self.saved.push(SavedEntry {
                address,
                value_type: vt,
                desc: String::new(),
                frozen: false,
                edit_text: String::new(),
                pointer: None,
                str_len,
            });
        }
    }

    fn saved_table(&mut self, ui: &mut egui::Ui) {
        ui.heading("Cheat Table");
        ui.label("Enderecos salvos — edite, escreva e congele valores.");
        ui.horizontal(|ui| {
            if ui.button("💾 Salvar tabela").clicked() {
                self.save_table_dialog();
            }
            if ui.button("📂 Carregar tabela").clicked() {
                self.load_table_dialog();
            }
            ui.weak(format!("{} entradas", self.saved.len()));
        });
        ui.weak(hotkeys::LEGEND);
        ui.separator();

        let handle = self.attached.clone();
        // resolve os enderecos (fixos ou via ponteiro) antes do loop mutavel
        let addrs: Vec<Option<u64>> = self.saved.iter().map(|e| self.entry_address(e)).collect();

        let mut remove: Option<usize> = None;
        let mut write_idx: Option<usize> = None;
        let mut ptr_scan_target: Option<u64> = None;
        let mut open_viewer: Option<u64> = None;
        let mut watch_addr: Option<(u64, ValueType)> = None;
        let mut frozen_changed = false;

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, e) in self.saved.iter_mut().enumerate() {
                let resolved = addrs[i];
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        match resolved {
                            Some(a) => ui.monospace(format!("{a:016X}")),
                            None => ui.colored_label(egui::Color32::DARK_RED, "??? (não resolvido)"),
                        };
                        ui.label(format!("[{}]", e.value_type.label()));
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                    });
                    if let Some(p) = &e.pointer {
                        ui.monospace(egui::RichText::new(p.format()).small());
                    }
                    ui.horizontal(|ui| {
                        ui.label("Desc:");
                        ui.text_edit_singleline(&mut e.desc);
                    });
                    ui.horizontal(|ui| {
                        let len = e.read_len();
                        let cur = if len == 0 {
                            "?".into()
                        } else {
                            handle
                                .as_ref()
                                .zip(resolved)
                                .and_then(|(h, a)| memory::read_bytes(h.raw(), a, len))
                                .map(|b| e.value_type.format(&b))
                                .unwrap_or_else(|| "?".into())
                        };
                        ui.label("Atual:");
                        ui.monospace(cur);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Novo:");
                        ui.text_edit_singleline(&mut e.edit_text);
                        if ui.button("Escrever").clicked() {
                            write_idx = Some(i);
                        }
                        if ui.checkbox(&mut e.frozen, "Congelar").changed() {
                            frozen_changed = true;
                        }
                    });
                    if let Some(a) = resolved {
                        ui.horizontal(|ui| {
                            if ui.small_button("🔍 viewer").clicked() {
                                open_viewer = Some(a);
                            }
                            if ui.small_button("o que escreve").clicked() {
                                watch_addr = Some((a, e.value_type));
                            }
                            if e.pointer.is_none()
                                && ui.small_button("pointer scan").clicked()
                            {
                                ptr_scan_target = Some(a);
                            }
                        });
                    }
                });
            }
        });

        if let Some(i) = remove {
            self.saved.remove(i);
            self.rebuild_frozen_targets();
        }
        if let Some(i) = write_idx {
            let addr = addrs.get(i).copied().flatten();
            if let (Some(h), Some(e), Some(a)) = (handle.as_ref(), self.saved.get(i), addr) {
                if let Some(bytes) = e.value_type.parse_to_bytes(&e.edit_text) {
                    if memory::write_bytes(h.raw(), a, &bytes) {
                        self.status = format!("Escrito em {a:016X}.");
                    } else {
                        self.status = "Falha ao escrever (protecao de memoria?).".into();
                    }
                } else {
                    self.status = "Valor a escrever invalido.".into();
                }
            }
        }
        if let Some(a) = ptr_scan_target {
            self.ptr_target_text = format!("{a:X}");
            self.tab = Tab::Pointer;
            self.status = format!("Alvo do pointer scan: {a:X}. Ajuste e clique Procurar.");
        }
        if let Some(a) = open_viewer {
            self.mv_addr_text = format!("{a:X}");
            self.tab = Tab::MemViewer;
        }
        if let Some((a, vt)) = watch_addr {
            self.value_type = vt;
            self.mv_addr_text = format!("{a:X}");
            self.tab = Tab::MemViewer;
            self.start_watch(a);
        }
        if frozen_changed {
            self.rebuild_frozen_targets();
        }
    }

    fn pointer_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pointer Scan");
        ui.label(
            "Acha cadeias estáveis (módulo.exe+offset → +o1 → +o2 …) que sempre levam ao endereço, \
             mesmo reiniciando o jogo.",
        );
        ui.add_space(4.0);

        let scanning = self.ptr_task.is_some();
        egui::Grid::new("ptr_ctrl")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Endereço alvo (hex):");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_target_text),
                );
                ui.end_row();
                ui.label("Offset máximo:");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_max_offset_text),
                );
                ui.end_row();
                ui.label("Profundidade máx (1-8):");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_depth_text),
                );
                ui.end_row();
                ui.label("Alinhamento:");
                ui.add_enabled(
                    !scanning,
                    egui::TextEdit::singleline(&mut self.ptr_align_text),
                );
                ui.end_row();
            });

        ui.horizontal(|ui| {
            let enabled = self.attached.is_some() && !scanning;
            if ui
                .add_enabled(enabled, egui::Button::new("Procurar cadeias"))
                .clicked()
            {
                self.do_pointer_scan();
            }
            if ui
                .add_enabled(!scanning, egui::Button::new("Limpar"))
                .clicked()
            {
                self.ptr_results.clear();
            }
        });

        if let Some(task) = &self.ptr_task {
            ui.add(
                egui::ProgressBar::new(task.progress.fraction())
                    .show_percentage()
                    .text(format!("{} cadeias", task.progress.matches_count())),
            );
            if ui.button("Cancelar").clicked() {
                task.progress.request_cancel();
            }
        }

        ui.separator();
        ui.label(format!(
            "Cadeias encontradas: {} (mostrando até 500). Quanto mais curtas e com offsets pequenos, \
             mais confiáveis.",
            self.ptr_results.len()
        ));

        // validação entre execuções: reabriu o jogo, reanexou, achou o novo
        // endereço do valor -> filtra as cadeias que ainda resolvem para ele.
        if !self.ptr_results.is_empty() {
            ui.horizontal(|ui| {
                ui.label("Validar — manter só as que resolvem p/ (hex):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.ptr_validate_text)
                        .desired_width(150.0),
                );
                if ui.button("Filtrar").clicked() {
                    match parse_addr(&self.ptr_validate_text) {
                        Some(a) => self.validate_chains(a),
                        None => self.status = "Endereço de validação inválido (hex).".into(),
                    }
                }
            });
            ui.weak(
                "Reabra o jogo, reanexe, ache o novo endereço do valor e filtre: sobram só as \
                 cadeias estáveis entre execuções.",
            );
        }

        let handle = self.attached.clone();
        let mut add_path: Option<PtrPath> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for path in self.ptr_results.iter().take(500) {
                ui.horizontal(|ui| {
                    // valor atual que a cadeia resolve agora (verificacao)
                    let resolved = handle.as_ref().and_then(|h| {
                        self.module_bases
                            .get(&path.module)
                            .and_then(|b| pointer::resolve(h.raw(), *b, path))
                    });
                    let tag = match resolved {
                        Some(a) => format!("→ {a:X}"),
                        None => "→ ?".into(),
                    };
                    if ui.small_button("+ tabela").clicked() {
                        add_path = Some(path.clone());
                    }
                    ui.monospace(path.format());
                    ui.weak(tag);
                });
            }
        });

        if let Some(path) = add_path {
            self.saved.push(SavedEntry {
                address: 0,
                value_type: self.value_type,
                desc: format!("ptr {}", path.module),
                frozen: false,
                edit_text: String::new(),
                pointer: Some(path),
                str_len: 0,
            });
            self.status = "Cadeia adicionada à cheat table (endereço resolvido dinamicamente).".into();
        }
    }

    /// Adiciona um endereço fixo à cheat table com o tipo de valor atual.
    fn add_table_entry(&mut self, addr: u64) {
        let str_len = if self.value_type.is_string() { 16 } else { 0 };
        self.saved.push(SavedEntry {
            address: addr,
            value_type: self.value_type,
            desc: String::new(),
            frozen: false,
            edit_text: String::new(),
            pointer: None,
            str_len,
        });
        self.status = format!("{addr:016X} adicionado à tabela.");
    }

    /// Inicia um watch ("o que escreve/acessa aqui") via debugger.
    fn start_watch(&mut self, addr: u64) {
        if self.injection_blocked() {
            self.status = "Bloqueado: anticheat kernel detectado.".into();
            return;
        }
        let Some(h) = &self.attached else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let size = if self.value_type.is_string() {
            1
        } else {
            self.value_type.size()
        };
        let kind = if self.mv_watch_access {
            debugger::BreakKind::Access
        } else {
            debugger::BreakKind::Write
        };
        self.mv_watch = Some(debugger::start(h.pid, addr, size, kind));
        self.status = format!("Monitorando {addr:016X}… interaja com o jogo para coletar.");
    }

    fn mem_viewer_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Memory Viewer");
        let Some(h) = self.attached.clone() else {
            ui.label("Anexe um processo para inspecionar a memória.");
            return;
        };

        // navegação
        let mut goto: Option<u64> = None;
        ui.horizontal(|ui| {
            ui.label("Endereço (hex):");
            ui.add(egui::TextEdit::singleline(&mut self.mv_addr_text).desired_width(170.0));
            let cur = parse_addr(&self.mv_addr_text);
            if ui.button("◀ −80").clicked() {
                if let Some(a) = cur {
                    goto = Some(a.wrapping_sub(0x80));
                }
            }
            if ui.button("+80 ▶").clicked() {
                if let Some(a) = cur {
                    goto = Some(a.wrapping_add(0x80));
                }
            }
            ui.separator();
            ui.selectable_value(&mut self.mv_view, MvView::Hex, "Hex");
            ui.selectable_value(&mut self.mv_view, MvView::Disasm, "Disassembly");
        });
        if let Some(a) = goto {
            self.mv_addr_text = format!("{a:X}");
        }

        let Some(base) = parse_addr(&self.mv_addr_text) else {
            ui.separator();
            ui.label("Digite um endereço em hexadecimal (ex.: 7FF6 0001 2340).");
            return;
        };

        ui.separator();
        const WINDOW: usize = 512;
        let data = memory::read_bytes(h.raw(), base, WINDOW).unwrap_or_default();
        if data.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                "Não foi possível ler memória neste endereço.",
            );
        }

        match self.mv_view {
            MvView::Hex => {
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        ui.monospace(hex_dump_at(base, &data));
                    });
            }
            MvView::Disasm => {
                self.mv_disasm(ui, &h, base, &data);
            }
        }

        ui.separator();
        self.mv_watch_ui(ui, &h, base);
    }

    fn mv_disasm(
        &mut self,
        ui: &mut egui::Ui,
        h: &Arc<OpenProcessHandle>,
        base: u64,
        data: &[u8],
    ) {
        let insns = disasm::disassemble(data, base, 48);
        let blocked = self.injection_blocked();
        let mut nop_at: Option<(u64, usize)> = None;
        let mut add_tbl: Option<u64> = None;
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                egui::Grid::new("disasm")
                    .striped(true)
                    .num_columns(4)
                    .show(ui, |ui| {
                        for ins in &insns {
                            ui.monospace(format!("{:016X}", ins.address));
                            ui.monospace(disasm::fmt_bytes(&ins.bytes));
                            ui.monospace(&ins.text);
                            ui.horizontal(|ui| {
                                if !blocked && ui.small_button("NOP").clicked() {
                                    nop_at = Some((ins.address, ins.len));
                                }
                                if ui.small_button("+tabela").clicked() {
                                    add_tbl = Some(ins.address);
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
        if let Some((a, l)) = nop_at {
            if inject::nop(h.raw(), a, l) {
                self.status = format!("NOP em {a:016X} ({l} bytes).");
            } else {
                self.status = "Falha ao aplicar NOP.".into();
            }
        }
        if let Some(a) = add_tbl {
            self.add_table_entry(a);
        }
    }

    fn mv_watch_ui(&mut self, ui: &mut egui::Ui, h: &Arc<OpenProcessHandle>, base: u64) {
        ui.horizontal(|ui| {
            ui.strong("O que escreve/acessa este endereço");
            ui.checkbox(&mut self.mv_watch_access, "incluir leituras");
        });
        if self.injection_blocked() {
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                "Bloqueado: anticheat kernel detectado — anexar como debugger é detectável.",
            );
            return;
        }

        ui.horizontal(|ui| {
            if self.mv_watch.is_none() {
                if ui.button(format!("▶ monitorar {base:016X}")).clicked() {
                    self.start_watch(base);
                }
            } else if ui.button("⏹ parar").clicked() {
                self.mv_watch = None; // Drop encerra o debugger
                self.status = "Watch encerrado.".into();
            }
            if let Some(w) = &self.mv_watch {
                ui.weak(w.status());
            }
        });

        let Some(hits) = self.mv_watch.as_ref().map(|w| w.hits()) else {
            return;
        };
        ui.label(format!("{} instruções distintas", hits.len()));
        let mut goto: Option<u64> = None;
        let mut add: Option<u64> = None;
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .id_source("hits_scroll")
            .show(ui, |ui| {
                egui::Grid::new("hits")
                    .striped(true)
                    .num_columns(3)
                    .show(ui, |ui| {
                        ui.strong("Instrução que escreveu");
                        ui.strong("Vezes");
                        ui.strong("");
                        ui.end_row();
                        // a CPU trapa DEPOIS da escrita, entao o Rip aponta para a
                        // instrucao seguinte; recuperamos a que terminou nele.
                        const BACK: u64 = 16;
                        for hit in &hits {
                            let start = hit.rip.saturating_sub(BACK);
                            let writer = memory::read_bytes(h.raw(), start, BACK as usize)
                                .and_then(|b| disasm::instruction_ending_at(&b, start, hit.rip));
                            let (waddr, txt) = match writer {
                                Some(i) => (i.address, i.text),
                                None => (hit.rip, "? (anterior ao RIP)".to_string()),
                            };
                            ui.monospace(format!("{waddr:016X}  {txt}"));
                            ui.monospace(format!("{}", hit.count));
                            ui.horizontal(|ui| {
                                if ui.small_button("ir para").clicked() {
                                    goto = Some(waddr);
                                }
                                if ui.small_button("+tabela").clicked() {
                                    add = Some(waddr);
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
        if let Some(a) = goto {
            self.mv_addr_text = format!("{a:X}");
            self.mv_view = MvView::Disasm;
        }
        if let Some(a) = add {
            self.add_table_entry(a);
        }
    }

    fn run_assembler(&mut self, section: assembler::Section) {
        let Some(h) = self.attached.clone() else {
            self.status = "Anexe um processo primeiro.".into();
            return;
        };
        let name = if section == assembler::Section::Enable {
            "Enable"
        } else {
            "Disable"
        };
        match assembler::run_section(h.raw(), h.pid, &self.aa_script, section, &mut self.aa_state) {
            Ok(log) => {
                self.status = format!("{name} executado ({} passos).", log.len());
                self.aa_log = log;
            }
            Err(e) => {
                self.status = format!("{name} falhou: {e}");
                self.aa_log = vec![format!("ERRO: {e}")];
            }
        }
    }

    fn assembler_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Auto Assembler");
        if self.injection_blocked() {
            let name = self
                .detection
                .as_ref()
                .and_then(|d| d.protection.ac_name())
                .unwrap_or("anticheat kernel");
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                format!("🛡 {name} detectado — patch de código bloqueado. Use Kernel Exploring."),
            );
            return;
        }
        ui.label(
            "Scripts estilo Cheat Engine: AOB scan, code cave (alloc), patch e restauração. \
             Enable aplica, Disable desfaz.",
        );

        let enabled = self.attached.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(enabled, egui::Button::new("▶ Enable"))
                .clicked()
            {
                self.run_assembler(assembler::Section::Enable);
            }
            if ui
                .add_enabled(enabled, egui::Button::new("■ Disable"))
                .clicked()
            {
                self.run_assembler(assembler::Section::Disable);
            }
            if ui.button("Restaurar template").clicked() {
                self.aa_script = AA_TEMPLATE.to_string();
            }
        });

        ui.separator();
        egui::ScrollArea::vertical()
            .id_source("aa_editor")
            .max_height(360.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.aa_script)
                        .code_editor()
                        .desired_rows(18)
                        .desired_width(f32::INFINITY),
                );
            });

        ui.separator();
        ui.label("Log:");
        egui::ScrollArea::vertical()
            .id_source("aa_log")
            .max_height(160.0)
            .show(ui, |ui| {
                for l in &self.aa_log {
                    ui.monospace(l);
                }
            });
    }

    /// Badge colorido no top bar com o resultado da classificacao de AC.
    fn protection_badge(&self, ui: &mut egui::Ui) {
        match self.detection.as_ref().map(|d| &d.protection) {
            None => {
                ui.colored_label(egui::Color32::GRAY, "Proteção: —");
            }
            Some(anticheat::Protection::KernelAc(name)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                    format!("🛡 AC kernel: {name} (injeção bloqueada)"),
                );
            }
            Some(anticheat::Protection::UsermodeAc(name)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xE5, 0xC0, 0x7B),
                    format!("⚠ AC user-mode: {name}"),
                );
            }
            Some(anticheat::Protection::Unprotected) => {
                ui.colored_label(egui::Color32::LIGHT_GREEN, "✔ Sem AC kernel");
            }
        }
    }

    /// Painel da secao Kernel Exploring: mostra a classificacao e os metodos
    /// safe disponiveis (que nao tocam o processo protegido).
    fn kernel_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("🛡 Kernel Exploring (safe)");
        ui.label(
            "Análise de alvos protegidos por anticheat kernel (Vanguard, EAC, BattlEye…) \
             SEM injeção nem acesso ao processo — só métodos que respeitam o anticheat.",
        );
        ui.add_space(6.0);

        ui.group(|ui| {
            ui.strong("Classificação do alvo");
            match self.detection.as_ref() {
                None => {
                    ui.label("Anexe um processo para classificar.");
                }
                Some(det) => {
                    self.protection_badge(ui);
                    if det.reasons.is_empty() {
                        ui.weak("Nenhuma assinatura de anticheat encontrada.");
                    } else {
                        for r in &det.reasons {
                            ui.weak(format!("• {r}"));
                        }
                    }
                }
            }
        });

        ui.add_space(6.0);
        ui.strong("Métodos disponíveis");
        let mut goto: Option<Tab> = None;
        let mut method = |ui: &mut egui::Ui, name: &str, desc: &str, tab: Tab| {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::LIGHT_GREEN, "●");
                if ui.link(egui::RichText::new(name).strong()).clicked() {
                    goto = Some(tab);
                }
            });
            ui.weak(desc);
            ui.add_space(2.0);
        };
        method(
            ui,
            "Proxy HTTPS + CA própria",
            "Intercepta as APIs web/plataforma (login, loja, matchmaking) em texto puro — \
             estilo Burp, sem tocar no jogo.",
            Tab::Proxy,
        );
        method(
            ui,
            "Captura passiva (raw socket)",
            "Observa endpoints, portas, timing e volume na placa de rede. Conteúdo cifrado, \
             mas ótimo para Threat Intel / mapeamento de infra.",
            Tab::Capture,
        );

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.strong("🎮 Jogos nativos suportados");
            ui.weak(
                "Clientes com integração dedicada: o Quarry detecta o processo e fala com a \
                 API local do jogo — legítimo, sem injeção nem leitura de memória.",
            );
            ui.add_space(6.0);

            // League of Legends — API local do client (LCU).
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(0x1e, 0x90, 0xff), "●");
                ui.strong("League of Legends");
                match &self.lcu_conn {
                    Some(c) => {
                        ui.colored_label(
                            egui::Color32::LIGHT_GREEN,
                            format!("client selecionado · pid {} · 127.0.0.1:{}", c.pid, c.port),
                        );
                    }
                    None => {
                        ui.colored_label(egui::Color32::GRAY, "client não detectado");
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui.button("🔍 Detectar e selecionar").clicked() {
                    match lcu::discover() {
                        Ok(conn) => {
                            self.status = format!(
                                "League Client detectado (pid {}, porta {}).",
                                conn.pid, conn.port
                            );
                            self.lcu_conn = Some(conn);
                            goto = Some(Tab::Lcu);
                        }
                        Err(e) => {
                            self.lcu_conn = None;
                            self.status = format!("LCU: {e}");
                        }
                    }
                }
                if self.lcu_conn.is_some() && ui.button("Abrir API local ▸").clicked() {
                    goto = Some(Tab::Lcu);
                }
            });
        });

        if let Some(tab) = goto {
            self.tab = tab;
        }
    }

    fn capture_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Captura passiva");
        ui.label(
            "Observa o tráfego IPv4 da placa de rede (raw socket promíscuo), atribui cada \
             conversa ao processo dono do socket e guarda os pacotes para inspeção estilo \
             Wireshark. Fluxo: escolha o processo → veja as conversas dele → abra um pacote \
             para ver campos e o dump hex/ASCII. Não toca no processo: seguro sob anticheat \
             kernel. Conteúdo HTTPS é cifrado (TLS) — para ver path/URL/body decodificados \
             use o proxy MITM.",
        );
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let running = self.capture.is_some();
            ui.label("Interface (IPv4):");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.capture_iface).desired_width(140.0),
            );
            if !running {
                if ui.button("▶ Iniciar").clicked() {
                    match self.capture_iface.trim().parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => {
                            self.capture = Some(capture::start(ip));
                            self.capture_session_sel = None; // passa a ver o ao vivo
                            self.capture_pid = None;
                            self.capture_conv = None;
                            self.capture_pkt = None;
                            self.status = format!("Captura iniciada em {ip}.");
                        }
                        Err(_) => self.status = "IP da interface inválido.".into(),
                    }
                }
            } else if ui.button("■ Parar e salvar").clicked() {
                // congela o estado vivo numa sessão antes de encerrar as threads
                if let Some(cap) = self.capture.take() {
                    let name = format!("Captura {}", self.capture_sessions.len() + 1);
                    let s = snapshot_session(&cap.shared, &self.capture_iface, name);
                    let n = s.total_packets;
                    self.capture_sessions.push(s);
                    self.capture_session_sel = Some(self.capture_sessions.len() - 1);
                    self.capture_pid = None;
                    self.capture_conv = None;
                    self.capture_pkt = None;
                    self.status = format!("Captura parada e salva ({n} pacotes).");
                }
            }
            if let Some(c) = &self.capture {
                ui.colored_label(egui::Color32::LIGHT_GREEN, c.status());
            }
        });
        ui.weak(
            "Precisa rodar como Administrador. Loopback (127.0.0.1) e IPv6 não aparecem — \
             use o IP de uma placa real.",
        );

        // --- seletor de fonte: captura ao vivo ou sessões salvas ---
        if self.capture.is_some() || !self.capture_sessions.is_empty() {
            ui.horizontal(|ui| {
                ui.label("Fonte:");
                if self.capture.is_some()
                    && ui
                        .selectable_label(self.capture_session_sel.is_none(), "● ao vivo")
                        .clicked()
                {
                    self.capture_session_sel = None;
                    self.capture_pid = None;
                    self.capture_conv = None;
                    self.capture_pkt = None;
                }
                for i in 0..self.capture_sessions.len() {
                    let sel = self.capture_session_sel == Some(i);
                    let s = &self.capture_sessions[i];
                    let hover = format!(
                        "interface {} · {} conversas · {} pacotes · {}",
                        s.iface,
                        s.convs.len(),
                        s.total_packets,
                        human_bytes(s.total_bytes)
                    );
                    let name = s.name.clone();
                    if ui.selectable_label(sel, name).on_hover_text(hover).clicked() {
                        self.capture_session_sel = Some(i);
                        self.capture_pid = None;
                        self.capture_conv = None;
                        self.capture_pkt = None;
                    }
                }
            });
        }

        // ações da sessão salva selecionada (exportar / remover)
        if let Some(i) = self.capture_session_sel {
            ui.horizontal(|ui| {
                if ui.button("⬇ Exportar .pcap").clicked() {
                    let s = &self.capture_sessions[i];
                    let mut all: Vec<capture::PacketRecord> =
                        s.packets.values().flatten().cloned().collect();
                    all.sort_by_key(|p| p.ts_ms);
                    let fname = format!("quarry-{}.pcap", s.name.to_lowercase().replace(' ', "-"));
                    let path = std::path::PathBuf::from(&fname);
                    match write_pcap(&path, &all) {
                        Ok(()) => {
                            self.status =
                                format!("Exportados {} pacotes → {}", all.len(), path.display())
                        }
                        Err(e) => self.status = format!("Falha ao exportar .pcap: {e}"),
                    }
                }
                if ui.button("🗑 Remover sessão").clicked() {
                    self.capture_sessions.remove(i);
                    self.capture_session_sel = None;
                    self.capture_pid = None;
                    self.capture_conv = None;
                    self.capture_pkt = None;
                }
            });
        }

        // resolve a fonte ativa: sessão salva selecionada OU captura ao vivo
        let (convs, total_pkts, total_bytes): (Vec<capture::Conversation>, u64, u64) =
            if let Some(i) = self.capture_session_sel {
                let s = &self.capture_sessions[i];
                (s.convs.clone(), s.total_packets, s.total_bytes)
            } else if let Some(cap) = &self.capture {
                let sh = &cap.shared;
                (
                    sh.convs.lock().unwrap().clone(),
                    sh.total_packets.load(std::sync::atomic::Ordering::Relaxed),
                    sh.total_bytes.load(std::sync::atomic::Ordering::Relaxed),
                )
            } else {
                ui.separator();
                ui.weak("Inicie uma captura ou selecione uma sessão salva acima.");
                return;
            };

        ui.separator();

        // Trilha de navegacao (breadcrumb) processo › conversa › pacote
        ui.horizontal(|ui| {
            if ui.link("Processos").clicked() {
                self.capture_pid = None;
                self.capture_conv = None;
                self.capture_pkt = None;
            }
            if let Some(pid) = self.capture_pid {
                let name = convs
                    .iter()
                    .find(|c| c.pid == pid && !c.process.is_empty())
                    .map(|c| c.process.clone())
                    .unwrap_or_else(|| if pid == 0 { "(desconhecido)".into() } else { format!("pid {pid}") });
                ui.label("›");
                if ui.link(name).clicked() {
                    self.capture_conv = None;
                    self.capture_pkt = None;
                }
            }
            if let Some((proto, lport, rip, rport)) = self.capture_conv {
                ui.label("›");
                ui.monospace(format!(
                    "{} :{lport} ↔ {rip}:{rport}",
                    capture::proto_label(proto)
                ));
            }
        });

        if self.capture_pid.is_none() {
            self.capture_process_view(ui, &convs, total_pkts, total_bytes);
        } else if self.capture_conv.is_none() {
            self.capture_conv_view(ui, &convs);
        } else {
            // pacotes da conversa selecionada, vindos da fonte ativa
            let key = self.capture_conv.unwrap();
            let pkts: Vec<capture::PacketRecord> = if let Some(i) = self.capture_session_sel {
                self.capture_sessions[i]
                    .packets
                    .get(&key)
                    .cloned()
                    .unwrap_or_default()
            } else if let Some(cap) = &self.capture {
                cap.shared
                    .packets
                    .lock()
                    .unwrap()
                    .get(&key)
                    .map(|d| d.iter().cloned().collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            self.capture_packet_view(ui, &pkts);
        }
    }

    /// Nivel 1: lista de processos, agregando todas as conversas por PID.
    fn capture_process_view(
        &mut self,
        ui: &mut egui::Ui,
        convs: &[capture::Conversation],
        total_pkts: u64,
        total_bytes: u64,
    ) {
        struct Agg {
            name: String,
            convs: usize,
            packets: u64,
            bytes: u64,
            last_ms: u64,
        }
        let mut map: HashMap<u32, Agg> = HashMap::new();
        for c in convs {
            let e = map.entry(c.pid).or_insert_with(|| Agg {
                name: String::new(),
                convs: 0,
                packets: 0,
                bytes: 0,
                last_ms: 0,
            });
            if e.name.is_empty() && !c.process.is_empty() {
                e.name = c.process.clone();
            }
            e.convs += 1;
            e.packets += c.packets;
            e.bytes += c.bytes;
            e.last_ms = e.last_ms.max(c.last_ms);
        }
        let mut rows: Vec<(u32, Agg)> = map.into_iter().collect();
        rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));

        ui.horizontal(|ui| {
            ui.label(format!(
                "{} processos · {} conversas · {total_pkts} pacotes · {}",
                rows.len(),
                convs.len(),
                human_bytes(total_bytes)
            ));
            ui.separator();
            ui.label("Filtro:");
            ui.text_edit_singleline(&mut self.capture_filter);
        });

        let filter = self.capture_filter.to_lowercase();
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("capture_proc_grid")
                .num_columns(6)
                .striped(true)
                .spacing([14.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Processo");
                    ui.strong("PID");
                    ui.strong("Conversas");
                    ui.strong("Pacotes");
                    ui.strong("Volume");
                    ui.strong("Último (s)");
                    ui.end_row();

                    for (pid, a) in &rows {
                        let name = if !a.name.is_empty() {
                            a.name.clone()
                        } else if *pid == 0 {
                            "(desconhecido)".into()
                        } else {
                            format!("pid {pid}")
                        };
                        if !filter.is_empty()
                            && !name.to_lowercase().contains(&filter)
                            && !pid.to_string().contains(&filter)
                        {
                            continue;
                        }
                        if ui.selectable_label(false, &name).clicked() {
                            self.capture_pid = Some(*pid);
                            self.capture_conv = None;
                            self.capture_pkt = None;
                        }
                        ui.monospace(if *pid == 0 {
                            "—".into()
                        } else {
                            pid.to_string()
                        });
                        ui.label(a.convs.to_string());
                        ui.label(a.packets.to_string());
                        ui.label(human_bytes(a.bytes));
                        ui.label(format!("{:.1}", a.last_ms as f64 / 1000.0));
                        ui.end_row();
                    }
                });
        });
    }

    /// Nivel 2: conversas do processo selecionado.
    fn capture_conv_view(&mut self, ui: &mut egui::Ui, convs: &[capture::Conversation]) {
        let pid = self.capture_pid.unwrap();
        let mut list: Vec<&capture::Conversation> =
            convs.iter().filter(|c| c.pid == pid).collect();
        list.sort_by(|a, b| b.bytes.cmp(&a.bytes));

        ui.horizontal(|ui| {
            ui.label(format!("{} conversas", list.len()));
            ui.separator();
            ui.label("Filtro:");
            ui.text_edit_singleline(&mut self.capture_filter);
        });

        let filter = self.capture_filter.to_lowercase();
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("capture_conv_grid")
                .num_columns(6)
                .striped(true)
                .spacing([14.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Proto");
                    ui.strong("Porta local");
                    ui.strong("Endpoint remoto");
                    ui.strong("Pacotes");
                    ui.strong("Volume");
                    ui.strong("Último (s)");
                    ui.end_row();

                    for c in &list {
                        let remote = format!("{}:{}", c.remote_ip, c.remote_port);
                        if !filter.is_empty()
                            && !remote.to_lowercase().contains(&filter)
                            && !c.local_port.to_string().contains(&filter)
                            && !c.proto_name().to_lowercase().contains(&filter)
                        {
                            continue;
                        }
                        if ui.selectable_label(false, c.proto_name()).clicked() {
                            self.capture_conv = Some(c.key());
                            self.capture_pkt = None;
                        }
                        ui.monospace(c.local_port.to_string());
                        ui.monospace(remote);
                        ui.label(c.packets.to_string());
                        ui.label(human_bytes(c.bytes));
                        ui.label(format!("{:.1}", c.last_ms as f64 / 1000.0));
                        ui.end_row();
                    }
                });
        });
    }

    /// Nivel 3: pacotes da conversa selecionada + detalhe (campos + hex dump).
    /// Os pacotes vêm da fonte ativa (captura ao vivo ou sessão salva).
    fn capture_packet_view(&mut self, ui: &mut egui::Ui, pkts: &[capture::PacketRecord]) {
        if pkts.is_empty() {
            ui.weak("Sem pacotes capturados ainda para esta conversa.");
            return;
        }

        ui.label(format!(
            "{} pacotes (mantém os {} mais recentes). Arraste um pacote para o painel \
             Evidências à direita, ou use 📌.",
            pkts.len(),
            capture::MAX_PKTS_PER_CONV
        ));

        ui.columns(2, |cols| {
            // --- coluna esquerda: lista de pacotes (mais novo no topo) ---
            cols[0].label("Pacotes");
            egui::ScrollArea::vertical()
                .id_source("capture_pkt_list")
                .show(&mut cols[0], |ui| {
                    for (i, p) in pkts.iter().enumerate().rev() {
                        let arrow = if p.outbound { "▲" } else { "▼" };
                        let txt = format!(
                            "{arrow} {:>7.3}s  {}  {} B",
                            p.ts_ms as f64 / 1000.0,
                            p.proto_name(),
                            p.total_len
                        );
                        // clica para ver o detalhe; arrasta para o painel Evidências
                        let resp = ui
                            .selectable_label(self.capture_pkt == Some(i), txt)
                            .interact(egui::Sense::click_and_drag());
                        if resp.clicked() {
                            self.capture_pkt = Some(i);
                        }
                        if resp.drag_started() {
                            egui::DragAndDrop::set_payload(ui.ctx(), pinned_from(p));
                        }
                        if resp.dragged() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
                        }
                        resp.context_menu(|ui| {
                            if ui.button("📌 Fixar em Evidências").clicked() {
                                self.pinned.push(pinned_from(p));
                                ui.close_menu();
                            }
                        });
                    }
                });

            // --- coluna direita: detalhe do pacote selecionado ---
            let ui = &mut cols[1];
            ui.label("Detalhe");
            let Some(idx) = self.capture_pkt else {
                ui.weak("Selecione um pacote à esquerda.");
                return;
            };
            let Some(p) = pkts.get(idx) else {
                ui.weak("Selecione um pacote à esquerda.");
                return;
            };

            egui::ScrollArea::vertical()
                .id_source("capture_pkt_detail")
                .show(ui, |ui| {
                    if ui.button("📌 Fixar em Evidências").clicked() {
                        self.pinned.push(pinned_from(p));
                    }
                    ui.monospace(format!(
                        "{} {}  {}:{} {} {}:{}",
                        if p.outbound { "OUT" } else { "IN " },
                        p.proto_name(),
                        p.src,
                        p.src_port,
                        if p.outbound { "→" } else { "←" },
                        p.dst,
                        p.dst_port
                    ));
                    ui.monospace(format!(
                        "len {} B · t={:.3}s",
                        p.total_len,
                        p.ts_ms as f64 / 1000.0
                    ));

                    let payload = capture_l4_payload(p);
                    if let Some(line) = http_first_line(payload) {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::LIGHT_BLUE, format!("HTTP: {line}"));
                    } else if p.proto == 6 && (p.src_port == 443 || p.dst_port == 443) {
                        ui.add_space(4.0);
                        ui.colored_label(
                            egui::Color32::GRAY,
                            "Porta 443 — provável TLS (cifrado). Use o proxy MITM para decodificar.",
                        );
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(format!("Texto legível ({} bytes do payload):", payload.len()));
                    if payload.is_empty() {
                        ui.weak("(sem payload — só cabeçalhos, ex. ACK)");
                    } else {
                        ui.monospace(readable_text(payload));
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(format!("Hex dump ({} bytes do pacote IP):", p.data.len()));
                    ui.monospace(hex_dump(&p.data));
                });
        });
    }

    /// Painel direito da aba Captura: pacotes fixados como evidência. Aceita
    /// arrastar-e-soltar da lista de pacotes e mostra o detalhe do selecionado.
    fn evidence_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Evidências");
        ui.weak("Arraste um pacote da lista para cá (ou use 📌). Fica salvo aqui em destaque.");

        ui.horizontal(|ui| {
            if !self.pinned.is_empty() {
                if ui.button("⬇ Exportar .pcap").clicked() {
                    let recs: Vec<capture::PacketRecord> =
                        self.pinned.iter().map(|p| p.rec.clone()).collect();
                    let path = std::path::PathBuf::from("quarry-evidencias.pcap");
                    match write_pcap(&path, &recs) {
                        Ok(()) => {
                            self.status =
                                format!("Exportadas {} evidências → {}", recs.len(), path.display())
                        }
                        Err(e) => self.status = format!("Falha ao exportar: {e}"),
                    }
                }
                if ui.button("🧹 Limpar").clicked() {
                    self.pinned.clear();
                    self.pinned_sel = None;
                }
            }
        });
        ui.separator();

        // Zona de soltura: a lista de evidências em si aceita o pacote arrastado.
        let frame = egui::Frame::group(ui.style());
        let (_, payload) = ui.dnd_drop_zone::<PinnedPacket, _>(frame, |ui| {
            if self.pinned.is_empty() {
                ui.weak("(solte um pacote aqui)");
            }
            let mut remove: Option<usize> = None;
            for i in 0..self.pinned.len() {
                ui.horizontal(|ui| {
                    let sel = self.pinned_sel == Some(i);
                    if ui
                        .selectable_label(sel, &self.pinned[i].label)
                        .clicked()
                    {
                        self.pinned_sel = Some(i);
                    }
                    if ui.small_button("✖").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                self.pinned.remove(i);
                if self.pinned_sel == Some(i) {
                    self.pinned_sel = None;
                }
            }
        });
        if let Some(p) = payload {
            self.pinned.push((*p).clone());
            self.pinned_sel = Some(self.pinned.len() - 1);
        }

        // Detalhe da evidência selecionada.
        if let Some(pin) = self.pinned_sel.and_then(|i| self.pinned.get(i)) {
            let p = &pin.rec;
            ui.separator();
            egui::ScrollArea::vertical()
                .id_source("evidence_detail")
                .show(ui, |ui| {
                    ui.monospace(format!(
                        "{} {}  {}:{} {} {}:{}",
                        if p.outbound { "OUT" } else { "IN " },
                        p.proto_name(),
                        p.src,
                        p.src_port,
                        if p.outbound { "→" } else { "←" },
                        p.dst,
                        p.dst_port
                    ));
                    let payload = capture_l4_payload(p);
                    if let Some(line) = http_first_line(payload) {
                        ui.colored_label(egui::Color32::LIGHT_BLUE, format!("HTTP: {line}"));
                    }
                    if !payload.is_empty() {
                        ui.label(format!("Texto legível ({} bytes):", payload.len()));
                        ui.monospace(readable_text(payload));
                        ui.separator();
                    }
                    ui.label(format!("Hex dump ({} bytes):", p.data.len()));
                    ui.monospace(hex_dump(&p.data));
                });
        }
    }

    fn lcu_panel(&mut self, ui: &mut egui::Ui) {
        if ui.link("‹ Jogos nativos suportados").clicked() {
            self.tab = Tab::KernelOverview;
        }
        ui.heading("League of Legends — API local (LCU)");
        ui.label(
            "Fala com a API REST local do League Client (https://127.0.0.1) usando a porta e \
             o token do lockfile. Acesso legítimo, sem injeção nem leitura da memória do jogo.",
        );
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            if ui.button("🔍 Detectar client").clicked() {
                match lcu::discover() {
                    Ok(conn) => {
                        self.status = format!("LCU detectado (pid {}, porta {}).", conn.pid, conn.port);
                        self.lcu_conn = Some(conn);
                    }
                    Err(e) => {
                        self.lcu_conn = None;
                        self.status = format!("LCU: {e}");
                    }
                }
            }
            match &self.lcu_conn {
                Some(c) => ui.colored_label(
                    egui::Color32::LIGHT_GREEN,
                    format!("conectado · 127.0.0.1:{} (pid {})", c.port, c.pid),
                ),
                None => ui.colored_label(egui::Color32::GRAY, "não detectado"),
            };
        });

        let Some(conn) = self.lcu_conn.clone() else {
            ui.weak("Abra o League Client e clique em Detectar.");
            return;
        };

        ui.separator();
        ui.label("Atalhos:");
        ui.horizontal_wrapped(|ui| {
            let shortcuts = [
                ("Summoner atual", "/lol-summoner/v1/current-summoner"),
                ("Fase do jogo", "/lol-gameflow/v1/gameflow-phase"),
                ("Carteira (RP/BE)", "/lol-store/v1/wallet"),
                ("Amigos", "/lol-chat/v1/friends"),
                ("Sessão de seleção", "/lol-champ-select/v1/session"),
            ];
            for (name, path) in shortcuts {
                if ui.button(name).clicked() {
                    self.lcu_method = "GET".into();
                    self.lcu_path = path.into();
                    self.lcu_body.clear();
                }
            }
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_source("lcu_method")
                .selected_text(&self.lcu_method)
                .width(90.0)
                .show_ui(ui, |ui| {
                    for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                        ui.selectable_value(&mut self.lcu_method, m.to_string(), m);
                    }
                });
            ui.add(
                egui::TextEdit::singleline(&mut self.lcu_path)
                    .desired_width(f32::INFINITY)
                    .hint_text("/caminho/da/api"),
            );
        });

        if !matches!(self.lcu_method.as_str(), "GET" | "DELETE") {
            ui.label("Body (JSON):");
            ui.add(
                egui::TextEdit::multiline(&mut self.lcu_body)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
        }

        ui.horizontal(|ui| {
            let busy = self.lcu_busy;
            if ui.add_enabled(!busy, egui::Button::new("▶ Enviar")).clicked() {
                self.lcu_rx = Some(lcu::request(
                    &conn,
                    self.lcu_method.clone(),
                    self.lcu_path.clone(),
                    self.lcu_body.clone(),
                ));
                self.lcu_busy = true;
                self.lcu_status = 0;
                self.lcu_resp.clear();
            }
            if busy {
                ui.spinner();
            } else if self.lcu_status != 0 {
                let color = if self.lcu_status < 400 {
                    egui::Color32::LIGHT_GREEN
                } else {
                    egui::Color32::LIGHT_RED
                };
                ui.colored_label(color, format!("HTTP {}", self.lcu_status));
            }
        });

        if !self.lcu_resp.is_empty() {
            ui.separator();
            let mut resp = self.lcu_resp.clone(); // só exibição (read-only)
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut resp)
                        .desired_width(f32::INFINITY)
                        .interactive(false)
                        .code_editor(),
                );
            });
        }
    }

    fn proxy_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy HTTPS");
        ui.label(
            "Intercepta, edita e reenvia requisições/respostas HTTP(S) — estilo Burp. Não toca \
             no processo: funciona com qualquer alvo, inclusive sob anticheat kernel.",
        );
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let running = self.proxy.is_some();
            ui.label("Porta:");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.proxy_port_text).desired_width(70.0),
            );
            if !running {
                if ui.button("▶ Iniciar").clicked() {
                    match self.proxy_port_text.trim().parse::<u16>() {
                        Ok(port) => {
                            let p = proxy::start(port);
                            p.shared.set_rules(self.rules.clone());
                            self.proxy = Some(p);
                            self.status = format!("Proxy iniciado na porta {port}.");
                        }
                        Err(_) => self.status = "Porta inválida.".into(),
                    }
                }
            } else if ui.button("■ Parar").clicked() {
                self.proxy = None; // Drop encerra o proxy
                self.status = "Proxy parado.".into();
            }
            if let Some(p) = &self.proxy {
                ui.colored_label(egui::Color32::LIGHT_GREEN, p.status());
            }
        });

        if let Some(p) = &self.proxy {
            ui.horizontal(|ui| {
                ui.label("CA:");
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(p.ca_path.display().to_string()).monospace(),
                    )
                    .selectable(true),
                );
            });
            ui.weak(
                "Instale esse arquivo como Autoridade Certificadora Raiz confiável e aponte o \
                 proxy do sistema/jogo para 127.0.0.1 na porta acima para ver HTTPS.",
            );
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.proxy_view, ProxyView::History, "Histórico");
            let pending = self.proxy.as_ref().map(|p| p.shared.pending_count()).unwrap_or(0);
            let label = if pending > 0 {
                format!("Intercept ({pending})")
            } else {
                "Intercept".to_string()
            };
            ui.selectable_value(&mut self.proxy_view, ProxyView::Intercept, label);
            ui.selectable_value(&mut self.proxy_view, ProxyView::Repeater, "Repeater");
            ui.selectable_value(&mut self.proxy_view, ProxyView::Rules, "Match & Replace");
        });
        ui.separator();

        match self.proxy_view {
            ProxyView::History => self.proxy_history(ui),
            ProxyView::Intercept => self.proxy_intercept(ui),
            ProxyView::Repeater => self.proxy_repeater(ui),
            ProxyView::Rules => self.proxy_rules(ui),
        }
    }

    fn proxy_history(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filtro:");
            ui.text_edit_singleline(&mut self.proxy_filter);
            if ui.button("Limpar histórico").clicked() {
                if let Some(p) = &self.proxy {
                    p.shared.flows.lock().unwrap().clear();
                }
                self.proxy_selected = None;
            }
        });

        let flows: Vec<proxy::FlowRecord> = self
            .proxy
            .as_ref()
            .map(|p| p.shared.flows.lock().unwrap().clone())
            .unwrap_or_default();
        let filter = self.proxy_filter.to_lowercase();
        ui.label(format!("{} flows", flows.len()));

        egui::ScrollArea::vertical()
            .id_source("proxy_flows")
            .max_height(220.0)
            .show(ui, |ui| {
                egui::Grid::new("proxy_grid")
                    .striped(true)
                    .num_columns(4)
                    .show(ui, |ui| {
                        ui.strong("#");
                        ui.strong("Método");
                        ui.strong("Status");
                        ui.strong("URL");
                        ui.end_row();
                        for f in flows.iter().rev() {
                            if !filter.is_empty() && !f.url.to_lowercase().contains(&filter) {
                                continue;
                            }
                            let sel = self.proxy_selected == Some(f.id);
                            if ui.selectable_label(sel, f.id.to_string()).clicked() {
                                self.proxy_selected = Some(f.id);
                            }
                            ui.label(&f.method);
                            ui.label(if f.status == 0 {
                                "—".to_string()
                            } else {
                                f.status.to_string()
                            });
                            ui.label(&f.url);
                            ui.end_row();
                        }
                    });
            });

        let selected = self
            .proxy_selected
            .and_then(|id| flows.iter().find(|f| f.id == id).cloned());
        if let Some(f) = selected {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "{} {}  →  {}  ({} B req / {} B resp)",
                    f.method, f.url, f.status, f.req_len, f.resp_len
                ));
                if ui.button("→ Repeater").clicked() {
                    self.rep_method = f.method.clone();
                    self.rep_url = f.url.clone();
                    self.rep_headers = f.req_headers.clone();
                    self.rep_body = f.req_body.clone();
                    self.proxy_view = ProxyView::Repeater;
                }
            });
            egui::ScrollArea::vertical()
                .id_source("proxy_detail")
                .show(ui, |ui| {
                    ui.collapsing("Requisição", |ui| {
                        ui.monospace(&f.req_headers);
                        if !f.req_body.is_empty() {
                            ui.separator();
                            ui.monospace(&f.req_body);
                        }
                    });
                    ui.collapsing("Resposta", |ui| {
                        ui.monospace(&f.resp_headers);
                        if !f.resp_body.is_empty() {
                            ui.separator();
                            ui.monospace(&f.resp_body);
                        }
                    });
                });
        }
    }

    fn proxy_intercept(&mut self, ui: &mut egui::Ui) {
        let Some(shared) = self.proxy.as_ref().map(|p| p.shared.clone()) else {
            ui.weak("Inicie o proxy para interceptar.");
            return;
        };

        let mut on = shared.intercept_on();
        if ui
            .checkbox(&mut on, "Interceptar (pausar requisições antes de enviar)")
            .changed()
        {
            shared.set_intercept(on);
        }
        ui.separator();

        let Some(view) = shared.first_pending() else {
            ui.weak(if on {
                "Aguardando requisição…"
            } else {
                "Intercept desligado."
            });
            return;
        };

        // Carrega os buffers editáveis quando chega um item novo.
        if self.icpt_id != Some(view.id) {
            self.icpt_id = Some(view.id);
            self.icpt_headers = view.headers.clone();
            self.icpt_body = view.body.clone();
            self.icpt_follow = false;
        }

        let is_req = view.kind == proxy::InterceptKind::Request;
        ui.strong(format!(
            "{} — {} {}",
            if is_req { "Requisição" } else { "Resposta" },
            view.method,
            view.url
        ));
        if !is_req {
            ui.label(format!("Status {}", view.status));
        }

        ui.label("Headers:");
        ui.add(
            egui::TextEdit::multiline(&mut self.icpt_headers)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.label("Body:");
        ui.add(
            egui::TextEdit::multiline(&mut self.icpt_body)
                .code_editor()
                .desired_rows(8)
                .desired_width(f32::INFINITY),
        );
        if is_req {
            ui.checkbox(&mut self.icpt_follow, "Interceptar a resposta também");
        }

        let mut forward = false;
        let mut forward_follow = false;
        let mut drop = false;
        let mut to_repeater = false;
        ui.horizontal(|ui| {
            let fwd = ui.button("▶ Forward");
            if is_req {
                fwd.context_menu(|ui| {
                    if ui.button("Forward interceptando a resposta").clicked() {
                        forward_follow = true;
                        ui.close_menu();
                    }
                });
            }
            if fwd.clicked() {
                forward = true;
            }
            if ui.button("✖ Drop").clicked() {
                drop = true;
            }
            if is_req && ui.button("→ Repeater").clicked() {
                to_repeater = true;
            }
        });

        if forward || forward_follow {
            shared.resolve(
                view.id,
                proxy::Decision::Forward {
                    headers: self.icpt_headers.clone(),
                    body: self.icpt_body.clone(),
                    intercept_response: self.icpt_follow || forward_follow,
                },
            );
            self.icpt_id = None;
        } else if drop {
            shared.resolve(view.id, proxy::Decision::Drop);
            self.icpt_id = None;
        }
        if to_repeater {
            self.rep_method = view.method.clone();
            self.rep_url = view.url.clone();
            self.rep_headers = self.icpt_headers.clone();
            self.rep_body = self.icpt_body.clone();
            self.proxy_view = ProxyView::Repeater;
        }
    }

    fn proxy_repeater(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Método:");
            ui.add(egui::TextEdit::singleline(&mut self.rep_method).desired_width(70.0));
            ui.label("URL:");
            ui.add(
                egui::TextEdit::singleline(&mut self.rep_url).desired_width(f32::INFINITY),
            );
        });
        ui.label("Headers:");
        ui.add(
            egui::TextEdit::multiline(&mut self.rep_headers)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.label("Body:");
        ui.add(
            egui::TextEdit::multiline(&mut self.rep_body)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );

        ui.horizontal(|ui| {
            let can = self.proxy.is_some() && !self.rep_busy;
            if ui.add_enabled(can, egui::Button::new("▶ Enviar")).clicked() {
                let rx = self.proxy.as_ref().map(|p| {
                    p.repeater(
                        self.rep_method.clone(),
                        self.rep_url.clone(),
                        self.rep_headers.clone(),
                        self.rep_body.clone(),
                    )
                });
                if let Some(rx) = rx {
                    self.rep_rx = Some(rx);
                    self.rep_busy = true;
                }
            }
            if self.proxy.is_none() {
                ui.weak("(inicie o proxy para usar o Repeater)");
            }
            if self.rep_busy {
                ui.spinner();
                ui.label("enviando…");
            }
        });

        ui.separator();
        ui.strong(format!(
            "Resposta: {}",
            if self.rep_status == 0 {
                "—".to_string()
            } else {
                self.rep_status.to_string()
            }
        ));
        egui::ScrollArea::vertical()
            .id_source("rep_resp")
            .show(ui, |ui| {
                if !self.rep_resp_headers.is_empty() {
                    ui.monospace(&self.rep_resp_headers);
                    ui.separator();
                }
                if !self.rep_resp_body.is_empty() {
                    ui.monospace(&self.rep_resp_body);
                }
            });
    }

    fn proxy_rules(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "Regras aplicadas automaticamente a toda mensagem (ex.: trocar dano=10 por \
             dano=9999). Substring ou regex.",
        );
        if ui.button("+ Nova regra").clicked() {
            self.rules.push(proxy::Rule {
                enabled: true,
                target: proxy::RuleTarget::RequestBody,
                is_regex: false,
                pattern: String::new(),
                replacement: String::new(),
            });
        }
        ui.separator();

        let mut remove: Option<usize> = None;
        egui::ScrollArea::vertical()
            .id_source("rules")
            .show(ui, |ui| {
                for (i, r) in self.rules.iter_mut().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut r.enabled, "ativa");
                            egui::ComboBox::from_id_source(format!("rt{i}"))
                                .selected_text(r.target.label())
                                .show_ui(ui, |ui| {
                                    for t in proxy::RuleTarget::ALL {
                                        ui.selectable_value(&mut r.target, t, t.label());
                                    }
                                });
                            ui.checkbox(&mut r.is_regex, "regex");
                            if ui.small_button("x").clicked() {
                                remove = Some(i);
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("Match:  ");
                            ui.add(
                                egui::TextEdit::singleline(&mut r.pattern)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Replace:");
                            ui.add(
                                egui::TextEdit::singleline(&mut r.replacement)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                    });
                }
            });
        if let Some(i) = remove {
            self.rules.remove(i);
        }

        // Sincroniza as regras com o runtime do proxy.
        if let Some(p) = &self.proxy {
            p.shared.set_rules(self.rules.clone());
        }
    }

    fn inject_panel(&mut self, ui: &mut egui::Ui) {
        let Some(h) = self.attached.clone() else {
            ui.heading("Injeção");
            ui.label("Anexe um processo primeiro (botão acima).");
            return;
        };
        // Trava de seguranca: com AC kernel, nao oferecemos injecao/patch.
        if self.injection_blocked() {
            ui.heading("Injeção");
            let name = self
                .detection
                .as_ref()
                .and_then(|d| d.protection.ac_name())
                .unwrap_or("anticheat kernel");
            ui.colored_label(
                egui::Color32::from_rgb(0xE0, 0x6C, 0x75),
                format!("🛡 {name} detectado — injeção e patch bloqueados."),
            );
            ui.label(
                "Injetar ou modificar este processo seria detectado/banido e foge do escopo \
                 da ferramenta. Use a seção Kernel Exploring para análise safe.",
            );
            if ui.button("Ir para Kernel Exploring").clicked() {
                self.section = Section::Kernel;
                self.tab = Tab::KernelOverview;
            }
            return;
        }
        let pid = h.pid;

        egui::ScrollArea::vertical().show(ui, |ui| {
            // ---------- Módulos ----------
            ui.heading("Módulos carregados");
            ui.horizontal(|ui| {
                if ui.button("Listar módulos").clicked() {
                    self.modules = inject::list_modules(pid);
                    self.status = format!("{} módulos.", self.modules.len());
                }
                ui.label("Filtro:");
                ui.text_edit_singleline(&mut self.module_filter);
            });
            let mf = self.module_filter.to_lowercase();
            egui::ScrollArea::vertical()
                .id_source("mods")
                .max_height(160.0)
                .show(ui, |ui| {
                    egui::Grid::new("modgrid").striped(true).num_columns(3).show(ui, |ui| {
                        ui.strong("Módulo");
                        ui.strong("Base");
                        ui.strong("Tamanho");
                        ui.end_row();
                        for m in &self.modules {
                            if !mf.is_empty() && !m.name.to_lowercase().contains(&mf) {
                                continue;
                            }
                            ui.label(&m.name);
                            ui.monospace(format!("{:016X}", m.base));
                            ui.monospace(format!("{:X}", m.size));
                            ui.end_row();
                        }
                    });
                });

            ui.separator();

            // ---------- AOB scan ----------
            ui.heading("AOB scan (padrão de bytes)");
            ui.label("Ex: 48 8B 05 ?? ?? ?? ?? 89   (?? = qualquer byte)");
            let aob_scanning = self.aob_task.is_some();
            ui.horizontal(|ui| {
                ui.add_enabled(
                    !aob_scanning,
                    egui::TextEdit::singleline(&mut self.aob_text),
                );
                if ui
                    .add_enabled(!aob_scanning, egui::Button::new("Procurar"))
                    .clicked()
                {
                    self.do_aob_scan();
                }
            });
            if let Some(task) = &self.aob_task {
                ui.add(
                    egui::ProgressBar::new(task.progress.fraction())
                        .show_percentage()
                        .text(format!("{} ocorrências", task.progress.matches_count())),
                );
                if ui.button("Cancelar").clicked() {
                    task.progress.request_cancel();
                }
            }
            let mut aob_to_patch: Option<u64> = None;
            egui::ScrollArea::vertical()
                .id_source("aob")
                .max_height(140.0)
                .show(ui, |ui| {
                    for a in self.aob_results.iter().take(200) {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{:016X}", a));
                            if ui.small_button("→ patch").clicked() {
                                aob_to_patch = Some(*a);
                            }
                        });
                    }
                });
            if let Some(a) = aob_to_patch {
                self.patch_addr_text = format!("{a:X}");
                self.nop_addr_text = format!("{a:X}");
            }

            ui.separator();

            // ---------- Patch / NOP ----------
            ui.heading("Patch de bytes / NOP");
            egui::Grid::new("patchgrid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Endereço (hex):");
                ui.text_edit_singleline(&mut self.patch_addr_text);
                ui.end_row();
                ui.label("Bytes (hex):");
                ui.text_edit_singleline(&mut self.patch_bytes_text);
                ui.end_row();
            });
            ui.horizontal(|ui| {
                if ui.button("Escrever bytes").clicked() {
                    match (
                        parse_addr(&self.patch_addr_text),
                        inject::parse_hex_bytes(&self.patch_bytes_text),
                    ) {
                        (Some(addr), Some(bytes)) => {
                            let ok = inject::write_code(h.raw(), addr, &bytes);
                            self.status = if ok {
                                format!("Patch de {} bytes em {addr:X}.", bytes.len())
                            } else {
                                "Falha no patch.".into()
                            };
                        }
                        _ => self.status = "Endereço ou bytes inválidos.".into(),
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("NOP — endereço:");
                ui.text_edit_singleline(&mut self.nop_addr_text);
                ui.label("qtd:");
                ui.add(egui::TextEdit::singleline(&mut self.nop_len_text).desired_width(50.0));
                if ui.button("NOP").clicked() {
                    match (parse_addr(&self.nop_addr_text), self.nop_len_text.trim().parse::<usize>()) {
                        (Some(addr), Ok(len)) if len > 0 && len <= 256 => {
                            let ok = inject::nop(h.raw(), addr, len);
                            self.status = if ok {
                                format!("{len} NOP(s) em {addr:X}.")
                            } else {
                                "Falha no NOP.".into()
                            };
                        }
                        _ => self.status = "Endereço/quantidade inválidos (1..256).".into(),
                    }
                }
            });

            ui.separator();

            // ---------- Injeção de DLL ----------
            ui.heading("Injeção de DLL");
            ui.horizontal(|ui| {
                ui.label("Caminho .dll:");
                ui.text_edit_singleline(&mut self.dll_path);
            });
            if ui.button("Injetar DLL").clicked() {
                let path = self.dll_path.trim();
                if path.is_empty() || !std::path::Path::new(path).exists() {
                    self.status = "Arquivo .dll não encontrado.".into();
                } else {
                    match inject::inject_dll(h.raw(), path) {
                        Ok(code) if code != 0 => {
                            self.status = format!("DLL injetada (LoadLibrary retornou {code:#X}).")
                        }
                        Ok(_) => {
                            self.status =
                                "CreateRemoteThread rodou mas LoadLibrary retornou 0 (DLL falhou ao carregar — arquitetura x86/x64?)."
                                    .into()
                        }
                        Err(e) => self.status = format!("Falha na injeção: {e}"),
                    }
                }
            }
        });
    }
}

fn scan_kind_label(k: ScanKind) -> &'static str {
    match k {
        ScanKind::Exact => "Valor exato",
        ScanKind::BiggerThan => "Maior que",
        ScanKind::SmallerThan => "Menor que",
        ScanKind::Between => "Entre (intervalo)",
        ScanKind::Changed => "Mudou",
        ScanKind::Unchanged => "Nao mudou",
        ScanKind::Increased => "Aumentou",
        ScanKind::Decreased => "Diminuiu",
    }
}
