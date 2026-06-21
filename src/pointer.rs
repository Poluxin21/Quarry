//! Pointer scanner: descobre cadeias de ponteiros estaveis
//! (`modulo.exe+offset -> +o1 -> +o2 ...`) que sempre levam ao endereco alvo,
//! mesmo depois de reiniciar o jogo.
//!
//! Estrategia (igual ao Cheat Engine, busca reversa):
//! 1. Varre a memoria montando um "mapa de ponteiros": todo endereco A cujo
//!    conteudo [A] aponta para dentro da memoria committed do processo.
//! 2. A partir do alvo, anda para tras: procura A tal que `[A] + off == alvo`
//!    (com `off` ate `max_offset`). Cada A vira o novo alvo. Repete ate achar
//!    um A dentro de um modulo (endereco estatico) -> isso fecha a cadeia.

use std::sync::atomic::Ordering;

use windows::Win32::Foundation::HANDLE;

use crate::inject::ModuleInfo;
use crate::memory::{self, Region};
use crate::scan::ScanProgress;

/// Parametros da busca de ponteiros.
#[derive(Clone, Copy)]
pub struct PtrScanParams {
    pub target: u64,
    pub max_offset: u64,
    pub max_depth: usize,
    pub alignment: usize,
    pub max_results: usize,
}

/// Uma cadeia de ponteiros encontrada, do modulo ate o alvo.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PtrPath {
    pub module: String,
    pub base_offset: u64,
    /// offsets aplicados em cada deref, na ordem base -> alvo.
    pub offsets: Vec<u64>,
}

impl PtrPath {
    /// Texto no estilo Cheat Engine: `["game.exe"+1A2B]+10+8`
    pub fn format(&self) -> String {
        let mut s = format!("[\"{}\"+{:X}]", self.module, self.base_offset);
        for (i, off) in self.offsets.iter().enumerate() {
            if i + 1 == self.offsets.len() {
                s.push_str(&format!("+{off:X}"));
            } else {
                s = format!("[{s}+{off:X}]");
            }
        }
        s
    }
}

/// Conjunto de spans committed, para testar rapidamente se um valor "parece" ponteiro.
struct Committed {
    spans: Vec<(u64, u64)>, // (base, end), ordenado por base
}

impl Committed {
    fn from(regions: &[Region]) -> Self {
        let mut spans: Vec<(u64, u64)> =
            regions.iter().map(|r| (r.base, r.base + r.size as u64)).collect();
        spans.sort_by_key(|s| s.0);
        Self { spans }
    }

    fn contains(&self, addr: u64) -> bool {
        let i = self.spans.partition_point(|s| s.0 <= addr);
        if i == 0 {
            return false;
        }
        let (base, end) = self.spans[i - 1];
        addr >= base && addr < end
    }
}

/// Intervalos dos modulos, para identificar enderecos estaticos.
pub struct ModuleRanges {
    ranges: Vec<(u64, u64, String)>, // (base, end, nome), ordenado por base
}

impl ModuleRanges {
    pub fn from(mods: &[ModuleInfo]) -> Self {
        let mut ranges: Vec<(u64, u64, String)> = mods
            .iter()
            .map(|m| (m.base, m.base + m.size as u64, m.name.clone()))
            .collect();
        ranges.sort_by_key(|r| r.0);
        Self { ranges }
    }

    /// Se `addr` esta dentro de um modulo, retorna (nome, base do modulo).
    fn module_of(&self, addr: u64) -> Option<(&str, u64)> {
        let i = self.ranges.partition_point(|r| r.0 <= addr);
        if i == 0 {
            return None;
        }
        let (base, end, name) = &self.ranges[i - 1];
        if addr >= *base && addr < *end {
            Some((name.as_str(), *base))
        } else {
            None
        }
    }
}

/// Monta o mapa de ponteiros: pares (valor_apontado, endereco_que_contem), ordenado por valor.
fn build_pointer_map(
    handle: HANDLE,
    regions: &[Region],
    alignment: usize,
    committed: &Committed,
    progress: &ScanProgress,
) -> Vec<(u64, u64)> {
    let mut map: Vec<(u64, u64)> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let step = alignment.max(1);

    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) {
            break;
        }
        buf.clear();
        buf.resize(region.size, 0);
        if memory::read_into(handle, region.base, &mut buf) && region.size >= 8 {
            let end = region.size - 8;
            let mut off = 0usize;
            while off <= end {
                let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
                if v != 0 && committed.contains(v) {
                    map.push((v, region.base + off as u64));
                }
                off += step;
            }
        }
        progress.done.fetch_add(1, Ordering::Relaxed);
    }

    map.sort_by_key(|e| e.0);
    map
}

/// Busca reversa recursiva.
#[allow(clippy::too_many_arguments)]
fn search_rec(
    map: &[(u64, u64)],
    modules: &ModuleRanges,
    target: u64,
    params: &PtrScanParams,
    offsets: &mut Vec<u64>,
    results: &mut Vec<PtrPath>,
    progress: &ScanProgress,
) {
    if results.len() >= params.max_results || progress.cancel.load(Ordering::Relaxed) {
        return;
    }

    let lo = target.saturating_sub(params.max_offset);
    let start = map.partition_point(|e| e.0 < lo);

    let mut i = start;
    while i < map.len() && map[i].0 <= target {
        let (val, addr) = map[i];
        i += 1;

        let offset = target - val;
        offsets.push(offset);

        if let Some((name, mod_base)) = modules.module_of(addr) {
            let mut offs = offsets.clone();
            offs.reverse();
            results.push(PtrPath {
                module: name.to_string(),
                base_offset: addr - mod_base,
                offsets: offs,
            });
            progress.matches.store(results.len(), Ordering::Relaxed);
        } else if offsets.len() < params.max_depth {
            search_rec(map, modules, addr, params, offsets, results, progress);
        }

        offsets.pop();

        if results.len() >= params.max_results || progress.cancel.load(Ordering::Relaxed) {
            return;
        }
    }
}

/// Executa a busca completa (chamar numa thread de fundo).
pub fn pointer_scan(
    handle: HANDLE,
    regions: &[Region],
    modules: &ModuleRanges,
    params: PtrScanParams,
    progress: &ScanProgress,
) -> Vec<PtrPath> {
    let committed = Committed::from(regions);
    let map = build_pointer_map(handle, regions, params.alignment, &committed, progress);

    let mut results = Vec::new();
    let mut offsets = Vec::new();
    search_rec(&map, modules, params.target, &params, &mut offsets, &mut results, progress);
    results
}

/// Resolve uma cadeia para o endereco atual, dada a base do modulo no processo.
pub fn resolve(handle: HANDLE, module_base: u64, path: &PtrPath) -> Option<u64> {
    if path.offsets.is_empty() {
        return None;
    }
    let mut val = memory::read_u64(handle, module_base + path.base_offset)?;
    let last = path.offsets.len() - 1;
    for off in &path.offsets[..last] {
        val = memory::read_u64(handle, val.wrapping_add(*off))?;
    }
    Some(val.wrapping_add(path.offsets[last]))
}
