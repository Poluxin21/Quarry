//! Injecao e manipulacao de codigo: modulos, AOB scan, patch/NOP,
//! alocacao remota e injecao de DLL.

use std::ffi::c_void;
use std::sync::atomic::Ordering;

use windows::core::{s, w, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE,
    LPTHREAD_START_ROUTINE,
};

use crate::memory::{self, Region};
use crate::scan::ScanProgress;

/// Um modulo carregado no processo alvo (ex: game.exe, kernel32.dll).
#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u32,
    #[allow(dead_code)]
    pub path: String,
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Lista os modulos carregados no processo (base + tamanho).
pub fn list_modules(pid: u32) -> Vec<ModuleInfo> {
    let mut out = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut me = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if Module32FirstW(snap, &mut me).is_ok() {
            loop {
                out.push(ModuleInfo {
                    name: wide_to_string(&me.szModule),
                    base: me.modBaseAddr as u64,
                    size: me.modBaseSize,
                    path: wide_to_string(&me.szExePath),
                });
                if Module32NextW(snap, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// Converte um padrao tipo "48 8B 05 ?? ?? ?? ?? 89" em bytes opcionais.
/// `??` ou `?` = curinga (qualquer byte).
pub fn parse_aob(pattern: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "??" || tok == "?" {
            out.push(None);
        } else {
            out.push(Some(u8::from_str_radix(tok, 16).ok()?));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn matches_at(hay: &[u8], pat: &[Option<u8>]) -> bool {
    if hay.len() < pat.len() {
        return false;
    }
    pat.iter().zip(hay).all(|(p, &b)| match p {
        Some(x) => *x == b,
        None => true,
    })
}

/// Procura um padrao AOB em todas as regioes. Retorna ate `limit` enderecos.
pub fn aob_scan(
    handle: HANDLE,
    regions: &[Region],
    pat: &[Option<u8>],
    limit: usize,
) -> Vec<u64> {
    let mut found = Vec::new();
    if pat.is_empty() {
        return found;
    }
    let plen = pat.len();
    for region in regions {
        if found.len() >= limit {
            break;
        }
        let mut last_match: Option<u64> = None;
        memory::read_chunked(handle, region.base, region.size, plen - 1, &mut |cabs, data| {
            if found.len() >= limit || data.len() < plen {
                return;
            }
            let end = data.len() - plen;
            let mut i = 0usize;
            while i <= end {
                if matches_at(&data[i..], pat) {
                    let addr = cabs + i as u64;
                    if last_match.map_or(true, |l| addr > l) {
                        found.push(addr);
                        last_match = Some(addr);
                        if found.len() >= limit {
                            break;
                        }
                    }
                }
                i += 1;
            }
        });
    }
    found
}

/// Igual a [`aob_scan`], mas roda reportando progresso e atendendo cancelamento
/// (para execucao numa thread de fundo, reusando [`ScanProgress`]).
pub fn aob_scan_job(
    handle: HANDLE,
    regions: &[Region],
    pat: &[Option<u8>],
    limit: usize,
    progress: &ScanProgress,
) -> Vec<u64> {
    let mut found = Vec::new();
    if pat.is_empty() {
        return found;
    }
    let plen = pat.len();
    for region in regions {
        if progress.cancel.load(Ordering::Relaxed) || found.len() >= limit {
            break;
        }
        let mut last_match: Option<u64> = None;
        memory::read_chunked(handle, region.base, region.size, plen - 1, &mut |cabs, data| {
            if found.len() >= limit || data.len() < plen {
                return;
            }
            let end = data.len() - plen;
            let mut i = 0usize;
            while i <= end {
                if matches_at(&data[i..], pat) {
                    let addr = cabs + i as u64;
                    if last_match.map_or(true, |l| addr > l) {
                        found.push(addr);
                        last_match = Some(addr);
                        if found.len() >= limit {
                            break;
                        }
                    }
                }
                i += 1;
            }
        });
        progress.done.fetch_add(1, Ordering::Relaxed);
        progress.matches.store(found.len(), Ordering::Relaxed);
    }
    found
}

/// Escreve bytes em uma regiao de codigo, ajustando a protecao
/// temporariamente (PAGE_EXECUTE_READWRITE) e restaurando depois.
pub fn write_code(handle: HANDLE, address: u64, data: &[u8]) -> bool {
    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        if VirtualProtectEx(
            handle,
            address as *const c_void,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
        .is_err()
        {
            // tenta escrever mesmo assim (algumas paginas ja sao graváveis)
            return memory::write_bytes(handle, address, data);
        }
        let ok = memory::write_bytes(handle, address, data);
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            handle,
            address as *const c_void,
            data.len(),
            old,
            &mut tmp,
        );
        ok
    }
}

/// Substitui `len` bytes por NOP (0x90) — desativa uma instrucao.
pub fn nop(handle: HANDLE, address: u64, len: usize) -> bool {
    let nops = vec![0x90u8; len];
    write_code(handle, address, &nops)
}

/// Aloca memoria no processo alvo. Retorna o endereco base.
/// Bloco de construcao para code caves (ainda nao usado pela GUI).
#[allow(dead_code)]
pub fn alloc(handle: HANDLE, size: usize) -> Option<u64> {
    let p = unsafe {
        VirtualAllocEx(
            handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(p as u64)
    }
}

/// Libera memoria alocada com `alloc`.
#[allow(dead_code)]
pub fn free(handle: HANDLE, address: u64) -> bool {
    unsafe { VirtualFreeEx(handle, address as *mut c_void, 0, MEM_RELEASE).is_ok() }
}

/// Injeta uma DLL no processo alvo via LoadLibraryW + CreateRemoteThread.
/// Retorna Ok com o codigo de saida da thread (handle do modulo, truncado a 32 bits).
pub fn inject_dll(handle: HANDLE, dll_path: &str) -> Result<u32> {
    // caminho como UTF-16 terminado em nulo
    let mut wide: Vec<u16> = dll_path.encode_utf16().collect();
    wide.push(0);
    let bytes_len = wide.len() * 2;

    let remote = unsafe {
        VirtualAllocEx(handle, None, bytes_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote.is_null() {
        return Err(windows::core::Error::from_win32());
    }

    let path_bytes = unsafe {
        std::slice::from_raw_parts(wide.as_ptr() as *const u8, bytes_len)
    };
    if !memory::write_bytes(handle, remote as u64, path_bytes) {
        unsafe {
            let _ = VirtualFreeEx(handle, remote, 0, MEM_RELEASE);
        }
        return Err(windows::core::Error::from_win32());
    }

    // kernel32 is mapped at the same address across processes of the same
    // architecture, so LoadLibraryW can be resolved locally.
    let exit_code = unsafe {
        let kernel32 = GetModuleHandleW(w!("kernel32.dll"))?;
        let proc = GetProcAddress(kernel32, s!("LoadLibraryW"));
        let func = match proc {
            Some(f) => f,
            None => {
                let _ = VirtualFreeEx(handle, remote, 0, MEM_RELEASE);
                return Err(windows::core::Error::from_win32());
            }
        };
        let start: LPTHREAD_START_ROUTINE = Some(std::mem::transmute(func));

        let thread = CreateRemoteThread(handle, None, 0, start, Some(remote), 0, None)?;

        WaitForSingleObject(thread, INFINITE);
        let mut code = 0u32;
        let _ = GetExitCodeThread(thread, &mut code);
        let _ = CloseHandle(thread);
        let _ = VirtualFreeEx(handle, remote, 0, MEM_RELEASE);
        code
    };

    Ok(exit_code)
}

/// Converte uma string hex ("90 90 EB FE" ou "9090EBFE") em bytes.
pub fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let s = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
        i += 2;
    }
    Some(out)
}
