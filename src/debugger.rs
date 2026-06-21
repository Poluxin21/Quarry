//! "O que escreve/acessa este endereco" — debugger real estilo Cheat Engine.
//!
//! Anexa ao processo como debugger (`DebugActiveProcess`), arma um breakpoint de
//! HARDWARE (registradores DR0–DR7) no endereco alvo em todas as threads e roda
//! um loop de eventos. Quando a CPU dispara o breakpoint (a escrita ja ocorreu),
//! lemos o `Rip` da thread ofensora: e o endereco da instrucao que escreveu.
//! Agregamos por `Rip` com contagem.
//!
//! Limites: maximo de 4 breakpoints de HW por thread (usamos DR0); x64 apenas;
//! anexar como debugger pausa threads brevemente e e DETECTAVEL por anticheat —
//! por isso so deve ser usado em alvos da secao General (sem AC kernel).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{
    CloseHandle, BOOL, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    GetThreadContext, SetThreadContext, WaitForDebugEvent, CONTEXT, CONTEXT_FLAGS,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
};

/// Flags de CONTEXT (AMD64) para ler/escrever control + debug registers.
/// 0x00100000 = CONTEXT_AMD64, |0x1 = CONTROL (Rip), |0x10 = DEBUG_REGISTERS.
const DR_FLAGS: CONTEXT_FLAGS = CONTEXT_FLAGS(0x0010_0011);

/// Condicao do breakpoint de dados.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// So escrita (R/W = 01).
    Write,
    /// Leitura ou escrita (R/W = 11).
    Access,
}

/// Uma instrucao que tocou o endereco, com quantas vezes.
#[derive(Clone)]
pub struct WriteHit {
    pub rip: u64,
    pub count: u64,
}

struct Inner {
    hits: Mutex<Vec<WriteHit>>,
    stop: AtomicBool,
    status: Mutex<String>,
}

/// Handle de um watch em execucao. O Drop pede a parada do debugger.
pub struct WatchHandle {
    inner: Arc<Inner>,
}

impl WatchHandle {
    pub fn hits(&self) -> Vec<WriteHit> {
        let mut v = self.inner.hits.lock().unwrap().clone();
        v.sort_by(|a, b| b.count.cmp(&a.count));
        v
    }

    pub fn status(&self) -> String {
        self.inner.status.lock().unwrap().clone()
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
    }
}

/// Inicia o monitoramento de `addr` (de tamanho `size` bytes) no processo `pid`.
pub fn start(pid: u32, addr: u64, size: usize, kind: BreakKind) -> WatchHandle {
    let inner = Arc::new(Inner {
        hits: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        status: Mutex::new("anexando como debugger…".into()),
    });
    let inner_thread = inner.clone();
    std::thread::spawn(move || debug_loop(pid, addr, size, kind, inner_thread));
    WatchHandle { inner }
}

fn set_status(inner: &Inner, s: impl Into<String>) {
    *inner.status.lock().unwrap() = s.into();
}

fn record_hit(inner: &Inner, rip: u64) {
    let mut hits = inner.hits.lock().unwrap();
    if let Some(h) = hits.iter_mut().find(|h| h.rip == rip) {
        h.count += 1;
    } else {
        hits.push(WriteHit { rip, count: 1 });
    }
}

fn debug_loop(pid: u32, addr: u64, size: usize, kind: BreakKind, inner: Arc<Inner>) {
    unsafe {
        if DebugActiveProcess(pid).is_err() {
            set_status(
                &inner,
                "falha ao anexar como debugger (rode como Admin; outro debugger anexado?).",
            );
            return;
        }
        // fechar o Quarry NAO deve matar o alvo.
        let _ = DebugSetProcessKillOnExit(BOOL(0));
        set_status(&inner, "monitorando…");

        let rw: u64 = match kind {
            BreakKind::Write => 0b01,
            BreakKind::Access => 0b11,
        };
        // LEN: 1->00, 2->01, 8->10, 4->11
        let len: u64 = match size {
            1 => 0b00,
            2 => 0b01,
            8 => 0b10,
            _ => 0b11,
        };

        let mut threads: HashMap<u32, HANDLE> = HashMap::new();
        let mut event = DEBUG_EVENT::default();

        loop {
            if inner.stop.load(Ordering::Relaxed) {
                break;
            }
            // timeout curto para reavaliar o flag de parada.
            if WaitForDebugEvent(&mut event, 200).is_err() {
                continue;
            }

            let mut status = DBG_CONTINUE;
            let mut done = false;

            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = event.u.CreateProcessInfo;
                    threads.insert(event.dwThreadId, info.hThread);
                    arm_thread(info.hThread, addr, rw, len);
                    if !info.hFile.is_invalid() {
                        let _ = CloseHandle(info.hFile);
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let h = event.u.CreateThread.hThread;
                    threads.insert(event.dwThreadId, h);
                    arm_thread(h, addr, rw, len);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    threads.remove(&event.dwThreadId);
                }
                EXCEPTION_DEBUG_EVENT => {
                    let code = event.u.Exception.ExceptionRecord.ExceptionCode;
                    if code == EXCEPTION_SINGLE_STEP {
                        if let Some(&h) = threads.get(&event.dwThreadId) {
                            if let Some(rip) = consume_hit(h) {
                                record_hit(&inner, rip);
                            }
                        }
                        status = DBG_CONTINUE;
                    } else if code == EXCEPTION_BREAKPOINT {
                        // breakpoint inicial do debugger e afins: ignora.
                        status = DBG_CONTINUE;
                    } else {
                        // outras excecoes pertencem ao app.
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    done = true;
                }
                _ => {}
            }

            let _ = ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
            if done {
                break;
            }
        }

        let _ = DebugActiveProcessStop(pid);
        set_status(&inner, "parado.");
    }
}

/// Arma DR0 = addr com a condicao (rw/len) em DR7 para uma thread.
unsafe fn arm_thread(hthread: HANDLE, addr: u64, rw: u64, len: u64) {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = DR_FLAGS;
    if GetThreadContext(hthread, &mut ctx).is_err() {
        return;
    }
    ctx.Dr0 = addr;
    // limpa L0/G0 (bits 0-1) e RW0/LEN0 (bits 16-19), depois aplica.
    let dr7 = (1u64 << 0) | (rw << 16) | (len << 18);
    ctx.Dr7 = (ctx.Dr7 & !0x000F_0003u64) | dr7;
    ctx.Dr6 = 0;
    ctx.ContextFlags = DR_FLAGS;
    let _ = SetThreadContext(hthread, &ctx);
}

/// Le o Rip da thread que disparou DR0 e limpa DR6. None se nao foi o DR0.
unsafe fn consume_hit(hthread: HANDLE) -> Option<u64> {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = DR_FLAGS;
    if GetThreadContext(hthread, &mut ctx).is_err() {
        return None;
    }
    let was_dr0 = ctx.Dr6 & 0x1 != 0;
    let rip = ctx.Rip;
    // limpa os bits de status do DR6 para detectar o proximo disparo.
    ctx.Dr6 = 0;
    ctx.ContextFlags = DR_FLAGS;
    let _ = SetThreadContext(hthread, &ctx);
    if was_dr0 {
        Some(rip)
    } else {
        None
    }
}
