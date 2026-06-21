//! Disassembler x86-64 do Memory Viewer, sobre a crate `iced-x86`.
//!
//! Decodifica um buffer de bytes (lido da memoria do alvo) em instrucoes com
//! endereco, bytes crus e o mnemonico formatado (sintaxe Intel). x64 apenas,
//! coerente com o resto do Quarry.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

/// Uma instrucao decodificada.
#[derive(Clone)]
pub struct Insn {
    /// Endereco virtual da instrucao no alvo.
    pub address: u64,
    /// Comprimento em bytes.
    pub len: usize,
    /// Bytes crus da instrucao.
    pub bytes: Vec<u8>,
    /// Texto formatado (ex.: "mov rax,[rbx+10h]").
    pub text: String,
}

/// Decodifica ate `max` instrucoes de `code`, assumindo que o primeiro byte
/// esta no endereco virtual `rip`.
pub fn disassemble(code: &[u8], rip: u64, max: usize) -> Vec<Insn> {
    let mut decoder = Decoder::with_ip(64, code, rip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();
    let mut text = String::new();
    let mut out = Vec::with_capacity(max);

    while decoder.can_decode() && out.len() < max {
        decoder.decode_out(&mut instr);
        text.clear();
        formatter.format(&instr, &mut text);

        let start = (instr.ip().wrapping_sub(rip)) as usize;
        let len = instr.len();
        let bytes = code.get(start..start + len).unwrap_or(&[]).to_vec();

        out.push(Insn {
            address: instr.ip(),
            len,
            bytes,
            text: text.clone(),
        });
    }
    out
}

/// Acha a instrucao que TERMINA exatamente em `end_rip`, dado um bloco `code`
/// cujo primeiro byte esta em `start_addr` (use `start_addr = end_rip - code.len()`).
///
/// Breakpoints de dados de hardware sao *traps*: disparam DEPOIS da instrucao
/// executar, entao o `Rip` reportado aponta para a instrucao SEGUINTE. Esta
/// funcao recupera a instrucao que realmente fez o acesso, decodificando para
/// frente e pegando a que casa o fim com `end_rip` (com fallback para a ultima
/// antes de `end_rip` caso o inicio caia no meio de uma instrucao).
pub fn instruction_ending_at(code: &[u8], start_addr: u64, end_rip: u64) -> Option<Insn> {
    let insns = disassemble(code, start_addr, 64);
    if let Some(i) = insns.iter().find(|i| i.address + i.len as u64 == end_rip) {
        return Some(i.clone());
    }
    insns.into_iter().filter(|i| i.address < end_rip).last()
}

/// Formata os bytes de uma instrucao como hex ("48 8b 05").
pub fn fmt_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
