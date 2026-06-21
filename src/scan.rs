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
    /// valor dentro do intervalo [v1, v2] (inclusive).
    Between,
    /// comparacoes relativas ao scan anterior (so no next scan)
    Changed,
    Unchanged,
    Increased,
    Decreased,
}

impl ScanKind {
    /// Precisa de pelo menos um valor digitado.
    pub fn needs_value(&self) -> bool {
        matches!(
            self,
            ScanKind::Exact | ScanKind::BiggerThan | ScanKind::SmallerThan | ScanKind::Between
        )
    }

    /// Precisa de dois valores (intervalo).
    pub fn needs_two(&self) -> bool {
        matches!(self, ScanKind::Between)
    }
}

/// Parametros de comparacao por valor, ja com os alvos decodificados de forma
/// precisa para inteiros (i128) e para floats (f64).
#[derive(Clone, Copy)]
pub struct ScanCmp {
    pub kind: ScanKind,
    pub t1_i: i128,
    pub t2_i: i128,
    pub t1_f: f64,
    pub t2_f: f64,
}

impl ScanCmp {
    /// Comparacao relativa (changed/unchanged/...) sem alvo, para next scan.
    pub fn relative(kind: ScanKind) -> Self {
        Self { kind, t1_i: 0, t2_i: 0, t1_f: 0.0, t2_f: 0.0 }
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
    cmp: ScanCmp,
    progress: &ScanProgress,
) -> Vec<Match> {
    let mut matches = Vec::new();
    let size = value_type.size();
    if size == 0 {
        return matches;
    }
    let step = if fast_scan { size } else { 1 };

    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        // ultimo endereco ja emitido nesta regiao (dedup da zona de overlap)
        let mut last_match: Option<u64> = None;
        let region_base = region.base;
        memory::read_chunked(handle, region.base, region.size, size - 1, &mut |cabs, data| {
            // realinha o inicio do bloco em relacao a region.base, para testar
            // exatamente os mesmos enderecos que uma varredura continua testaria.
            let rel = (cabs - region_base) as usize;
            let mut i = if fast_scan {
                let m = rel % size;
                if m == 0 { 0 } else { size - m }
            } else {
                0
            };
            while i + size <= data.len() {
                let slice = &data[i..i + size];
                if compare(value_type, &cmp, slice, f64::NAN).unwrap_or(false) {
                    let addr = cabs + i as u64;
                    if last_match.map_or(true, |l| addr > l) {
                        let last = value_type.read_f64(slice).unwrap_or(0.0);
                        matches.push(Match { address: addr, last });
                        last_match = Some(addr);
                    }
                }
                i += step;
            }
        });
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
    cmp: ScanCmp,
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
        let keep = compare(value_type, &cmp, &buf, m.last).unwrap_or(false);
        if keep {
            m.last = value_type.read_f64(&buf).unwrap_or(m.last);
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
    let plen = pattern.len();

    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut last_match: Option<u64> = None;
        memory::read_chunked(handle, region.base, region.size, plen - 1, &mut |cabs, data| {
            if data.len() < plen {
                return;
            }
            let end = data.len() - plen;
            let mut i = 0usize;
            while i <= end {
                if data[i] == first && &data[i..i + plen] == pattern {
                    let addr = cabs + i as u64;
                    if last_match.map_or(true, |l| addr > l) {
                        matches.push(Match { address: addr, last: 0.0 });
                        last_match = Some(addr);
                    }
                }
                i += 1;
            }
        });
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

/// Snapshot de memoria para a busca de "valor inicial desconhecido": guarda os
/// bytes das regioes gravaveis no momento do first scan, para que o next scan
/// compare (mudou/aumentou/...) contra esse retrato.
pub struct Snapshot {
    pub regions: Vec<(u64, Vec<u8>)>,
}

/// Limites para o snapshot nao estourar a memoria (so regioes gravaveis).
const SNAP_MAX_REGION: usize = 256 * 1024 * 1024;
const SNAP_MAX_TOTAL: usize = 2 * 1024 * 1024 * 1024;

/// First scan de valor desconhecido: tira um retrato das regioes gravaveis.
pub fn unknown_first_job(
    handle: HANDLE,
    regions: &[Region],
    progress: &ScanProgress,
) -> Snapshot {
    let mut snap: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut total = 0usize;
    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        if !region.writable || region.size == 0 || region.size > SNAP_MAX_REGION {
            continue;
        }
        if total + region.size > SNAP_MAX_TOTAL {
            break;
        }
        let mut data = vec![0u8; region.size];
        let mut any = false;
        memory::read_chunked(handle, region.base, region.size, 0, &mut |cabs, chunk| {
            let off = (cabs - region.base) as usize;
            if off + chunk.len() <= data.len() {
                data[off..off + chunk.len()].copy_from_slice(chunk);
                any = true;
            }
        });
        if any {
            total += data.len();
            snap.push((region.base, data));
            progress.matches.store(snap.len(), Ordering::Relaxed);
        }
    }
    Snapshot { regions: snap }
}

/// Next scan de valor desconhecido: re-le cada regiao e compara contra o snapshot.
pub fn unknown_next_job(
    handle: HANDLE,
    snap: &Snapshot,
    value_type: ValueType,
    fast_scan: bool,
    cmp: ScanCmp,
    progress: &ScanProgress,
) -> Vec<Match> {
    let mut matches = Vec::new();
    let size = value_type.size();
    if size == 0 {
        return matches;
    }
    let step = if fast_scan { size } else { 1 };

    for (base, old) in &snap.regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut cur = vec![0u8; old.len()];
        memory::read_chunked(handle, *base, old.len(), 0, &mut |cabs, chunk| {
            let off = (cabs - base) as usize;
            if off + chunk.len() <= cur.len() {
                cur[off..off + chunk.len()].copy_from_slice(chunk);
            }
        });
        let mut off = 0usize;
        while off + size <= old.len() {
            let oldb = &old[off..off + size];
            let newb = &cur[off..off + size];
            if compare_pair(value_type, &cmp, oldb, newb).unwrap_or(false) {
                let last = value_type.read_f64(newb).unwrap_or(0.0);
                matches.push(Match { address: base + off as u64, last });
            }
            off += step;
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
        progress.matches.store(matches.len(), Ordering::Relaxed);
    }
    matches
}

/// Comparacao precisa com o valor antigo em bytes (para o snapshot de valor
/// desconhecido): kinds por valor usam `c`; relativos comparam novo vs antigo.
fn compare_pair(vt: ValueType, c: &ScanCmp, oldb: &[u8], newb: &[u8]) -> Option<bool> {
    if vt.is_float() {
        let n = vt.read_f64(newb)?;
        Some(match c.kind {
            ScanKind::Exact => n == c.t1_f,
            ScanKind::BiggerThan => n > c.t1_f,
            ScanKind::SmallerThan => n < c.t1_f,
            ScanKind::Between => n >= c.t1_f && n <= c.t2_f,
            ScanKind::Changed => n != vt.read_f64(oldb)?,
            ScanKind::Unchanged => n == vt.read_f64(oldb)?,
            ScanKind::Increased => n > vt.read_f64(oldb)?,
            ScanKind::Decreased => n < vt.read_f64(oldb)?,
        })
    } else {
        let n = vt.read_i128(newb)?;
        Some(match c.kind {
            ScanKind::Exact => n == c.t1_i,
            ScanKind::BiggerThan => n > c.t1_i,
            ScanKind::SmallerThan => n < c.t1_i,
            ScanKind::Between => n >= c.t1_i && n <= c.t2_i,
            ScanKind::Changed => n != vt.read_i128(oldb)?,
            ScanKind::Unchanged => n == vt.read_i128(oldb)?,
            ScanKind::Increased => n > vt.read_i128(oldb)?,
            ScanKind::Decreased => n < vt.read_i128(oldb)?,
        })
    }
}

/// Compara o valor atual (`cur`, bytes lidos) segundo `c`. Inteiros sao
/// comparados em i128 (preciso ate u64/i64); floats em f64. `prev` e o valor
/// anterior (so usado nas comparacoes relativas). None se nao decodificar.
fn compare(vt: ValueType, c: &ScanCmp, cur: &[u8], prev: f64) -> Option<bool> {
    if vt.is_float() {
        let v = vt.read_f64(cur)?;
        Some(match c.kind {
            ScanKind::Exact => v == c.t1_f,
            ScanKind::BiggerThan => v > c.t1_f,
            ScanKind::SmallerThan => v < c.t1_f,
            ScanKind::Between => v >= c.t1_f && v <= c.t2_f,
            ScanKind::Changed => v != prev,
            ScanKind::Unchanged => v == prev,
            ScanKind::Increased => v > prev,
            ScanKind::Decreased => v < prev,
        })
    } else {
        let v = vt.read_i128(cur)?;
        let p = prev as i128;
        Some(match c.kind {
            ScanKind::Exact => v == c.t1_i,
            ScanKind::BiggerThan => v > c.t1_i,
            ScanKind::SmallerThan => v < c.t1_i,
            ScanKind::Between => v >= c.t1_i && v <= c.t2_i,
            ScanKind::Changed => v != p,
            ScanKind::Unchanged => v == p,
            ScanKind::Increased => v > p,
            ScanKind::Decreased => v < p,
        })
    }
}
