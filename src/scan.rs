//! Motor de busca: first scan e next scan, com suporte a execucao
//! em thread de fundo (progresso + cancelamento).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::memory::{self, Region};
use crate::value::ValueType;
use windows::Win32::Foundation::HANDLE;

/// Tipo de comparacao usada nas buscas.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanKind {
    Exact,
    BiggerThan,
    SmallerThan,
    /// comparacoes relativas ao scan anterior (so no next scan)
    Changed,
    Unchanged,
    Increased,
    Decreased,
}

impl ScanKind {
    pub fn needs_value(&self) -> bool {
        matches!(self, ScanKind::Exact | ScanKind::BiggerThan | ScanKind::SmallerThan)
    }
}

/// Um endereco encontrado com seu ultimo valor conhecido.
#[derive(Clone, Debug)]
pub struct Match {
    pub address: u64,
    pub last: f64,
}

/// Estado compartilhado entre a thread de busca e a UI.
pub struct ScanProgress {
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub matches: AtomicUsize,
    pub cancel: AtomicBool,
}

impl ScanProgress {
    pub fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            done: AtomicUsize::new(0),
            total: AtomicUsize::new(total.max(1)),
            matches: AtomicUsize::new(0),
            cancel: AtomicBool::new(false),
        })
    }

    pub fn fraction(&self) -> f32 {
        let total = self.total.load(Ordering::Relaxed).max(1);
        (self.done.load(Ordering::Relaxed) as f32 / total as f32).clamp(0.0, 1.0)
    }

    pub fn matches_count(&self) -> usize {
        self.matches.load(Ordering::Relaxed)
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Guarda o estado leve do scanner na UI (sem a logica pesada).
pub struct Scanner {
    #[allow(dead_code)]
    pub value_type: ValueType,
    pub fast_scan: bool,
    pub matches: Vec<Match>,
    pub has_scanned: bool,
}

impl Scanner {
    pub fn new(value_type: ValueType) -> Self {
        Self {
            value_type,
            fast_scan: true,
            matches: Vec::new(),
            has_scanned: false,
        }
    }

    pub fn reset(&mut self) {
        self.matches.clear();
        self.has_scanned = false;
    }
}

/// Primeira busca (roda na thread de fundo). Varre todas as regioes.
pub fn first_scan_job(
    handle: HANDLE,
    regions: &[Region],
    value_type: ValueType,
    fast_scan: bool,
    kind: ScanKind,
    target: f64,
    progress: &ScanProgress,
) -> Vec<Match> {
    let mut matches = Vec::new();
    let size = value_type.size();
    let step = if fast_scan { size } else { 1 };
    let mut buf: Vec<u8> = Vec::new();

    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        buf.clear();
        buf.resize(region.size, 0);
        let usable = if memory::read_into(handle, region.base, &mut buf) {
            region.size
        } else {
            0
        };
        if usable >= size {
            let mut off = 0usize;
            while off + size <= usable {
                if let Some(v) = value_type.read_f64(&buf[off..off + size]) {
                    if compare(kind, v, target, v) {
                        matches.push(Match {
                            address: region.base + off as u64,
                            last: v,
                        });
                    }
                }
                off += step;
            }
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        progress.matches.store(matches.len(), Ordering::Relaxed);
    }
    matches
}

/// Busca seguinte (roda na thread de fundo). Re-le cada endereco e filtra.
pub fn next_scan_job(
    handle: HANDLE,
    mut matches: Vec<Match>,
    value_type: ValueType,
    kind: ScanKind,
    target: f64,
    progress: &ScanProgress,
) -> Vec<Match> {
    let size = value_type.size();
    let mut buf = vec![0u8; size];
    let mut processed = 0usize;

    matches.retain_mut(|m| {
        if progress.cancel.load(Ordering::Relaxed) {
            return true; // mantem o resto intacto se cancelar
        }
        processed += 1;
        if processed % 4096 == 0 {
            progress.done.store(processed, Ordering::Relaxed);
        }
        if !memory::read_into(handle, m.address, &mut buf) {
            return false;
        }
        let current = match value_type.read_f64(&buf) {
            Some(v) => v,
            None => return false,
        };
        let keep = compare(kind, current, target, m.last);
        if keep {
            m.last = current;
        }
        keep
    });
    progress.done.store(processed, Ordering::Relaxed);
    progress.matches.store(matches.len(), Ordering::Relaxed);
    matches
}

/// Primeira busca de string: procura o padrao de bytes em todas as regioes.
pub fn first_scan_string_job(
    handle: HANDLE,
    regions: &[Region],
    pattern: &[u8],
    progress: &ScanProgress,
) -> Vec<Match> {
    let mut matches = Vec::new();
    if pattern.is_empty() {
        return matches;
    }
    let first = pattern[0];
    let mut buf: Vec<u8> = Vec::new();

    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        buf.clear();
        buf.resize(region.size, 0);
        if memory::read_into(handle, region.base, &mut buf) && region.size >= pattern.len() {
            let end = region.size - pattern.len();
            let mut i = 0usize;
            while i <= end {
                if buf[i] == first && &buf[i..i + pattern.len()] == pattern {
                    matches.push(Match {
                        address: region.base + i as u64,
                        last: 0.0,
                    });
                }
                i += 1;
            }
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        progress.matches.store(matches.len(), Ordering::Relaxed);
    }
    matches
}

/// Busca seguinte de string: mantem os enderecos que ainda contem o texto.
pub fn next_scan_string_job(
    handle: HANDLE,
    mut matches: Vec<Match>,
    pattern: &[u8],
    progress: &ScanProgress,
) -> Vec<Match> {
    if pattern.is_empty() {
        return matches;
    }
    let mut buf = vec![0u8; pattern.len()];
    let mut processed = 0usize;

    matches.retain_mut(|m| {
        if progress.cancel.load(Ordering::Relaxed) {
            return true;
        }
        processed += 1;
        if processed % 4096 == 0 {
            progress.done.store(processed, Ordering::Relaxed);
        }
        memory::read_into(handle, m.address, &mut buf) && buf == pattern
    });
    progress.done.store(processed, Ordering::Relaxed);
    progress.matches.store(matches.len(), Ordering::Relaxed);
    matches
}

/// `current` = valor atual lido; `target` = valor digitado; `previous` = valor anterior.
fn compare(kind: ScanKind, current: f64, target: f64, previous: f64) -> bool {
    match kind {
        ScanKind::Exact => current == target,
        ScanKind::BiggerThan => current > target,
        ScanKind::SmallerThan => current < target,
        ScanKind::Changed => current != previous,
        ScanKind::Unchanged => current == previous,
        ScanKind::Increased => current > previous,
        ScanKind::Decreased => current < previous,
    }
}
