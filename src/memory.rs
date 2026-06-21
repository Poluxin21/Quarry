//! Leitura/escrita de memoria e enumeracao de regioes.

use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY,
};

/// Uma regiao de memoria committed do processo.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: u64,
    pub size: usize,
    #[allow(dead_code)]
    pub writable: bool,
}

/// Le `len` bytes a partir de `address`. Retorna None se falhar.
pub fn read_bytes(handle: HANDLE, address: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut read),
        )
    };
    if ok.is_ok() && read == len {
        Some(buf)
    } else if ok.is_ok() && read > 0 {
        buf.truncate(read);
        Some(buf)
    } else {
        None
    }
}

/// Tamanho de bloco padrao para leitura em chunks (1 MiB).
pub const CHUNK: usize = 1024 * 1024;

/// Le uma regiao grande em blocos de `CHUNK` bytes, chamando `f(abs_offset, &dados)`
/// para cada bloco efetivamente lido. Blocos consecutivos se sobrepoem em `overlap`
/// bytes para nao perder um match que cruze a fronteira (use `item_size - 1`).
///
/// Ao contrario de [`read_into`], aceita leituras parciais: paginas ilegiveis no
/// meio da regiao apenas interrompem o bloco atual (o proximo bloco recomeca
/// depois). Mantem a memoria limitada a ~`CHUNK` em vez de alocar a regiao inteira.
pub fn read_chunked(
    handle: HANDLE,
    base: u64,
    size: usize,
    overlap: usize,
    f: &mut dyn FnMut(u64, &[u8]),
) {
    if size == 0 {
        return;
    }
    let step = CHUNK.saturating_sub(overlap).max(1);
    let mut off = 0usize;
    let mut buf = vec![0u8; CHUNK];
    while off < size {
        let want = CHUNK.min(size - off);
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                base.wrapping_add(off as u64) as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                want,
                Some(&mut read),
            )
        };
        if ok.is_ok() && read > 0 {
            f(base.wrapping_add(off as u64), &buf[..read]);
        }
        if ok.is_ok() && read == want {
            // bloco inteiro lido: avanca mantendo `overlap` bytes de sobreposicao
            off += step;
        } else {
            // pagina ilegivel adiante: pula a pagina problematica e continua
            // (um match nao pode cruzar uma pagina nao mapeada, entao nao ha perda)
            off += read.max(1) + 0x1000;
        }
    }
}

/// Le exatamente `buf.len()` bytes para dentro de `buf`. true se leu tudo.
pub fn read_into(handle: HANDLE, address: u64, buf: &mut [u8]) -> bool {
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            Some(&mut read),
        )
    };
    ok.is_ok() && read == buf.len()
}

/// Le um u64 (ponteiro x64) em `address`.
pub fn read_u64(handle: HANDLE, address: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    if read_into(handle, address, &mut buf) {
        Some(u64::from_le_bytes(buf))
    } else {
        None
    }
}

/// Escreve bytes em `address`. true se escreveu tudo.
pub fn write_bytes(handle: HANDLE, address: u64, data: &[u8]) -> bool {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            address as *const c_void,
            data.as_ptr() as *const c_void,
            data.len(),
            Some(&mut written),
        )
    };
    ok.is_ok() && written == data.len()
}

fn is_readable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    if protect.0 & (PAGE_GUARD.0 | PAGE_NOACCESS.0) != 0 {
        return false;
    }
    let readable = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_WRITECOPY.0;
    protect.0 & readable != 0
}

fn is_writable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    let writable = PAGE_READWRITE.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_WRITECOPY.0;
    protect.0 & writable != 0
}

/// Enumera todas as regioes committed e legiveis do processo.
pub fn enumerate_regions(handle: HANDLE) -> Vec<Region> {
    let mut regions = Vec::new();
    let mut address: u64 = 0;
    // limite superior do espaco de usuario em x64
    let max: u64 = 0x7FFF_FFFF_FFFF;

    unsafe {
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let written = VirtualQueryEx(
                handle,
                Some(address as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if written == 0 {
                break;
            }

            let region_base = mbi.BaseAddress as u64;
            let region_size = mbi.RegionSize;

            if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
                regions.push(Region {
                    base: region_base,
                    size: region_size,
                    writable: is_writable(mbi.Protect),
                });
            }

            let next = region_base.wrapping_add(region_size as u64);
            if next <= address || next >= max {
                break;
            }
            address = next;
        }
    }
    regions
}
