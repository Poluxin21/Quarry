//! Persistencia da cheat table em arquivo `.qct` (JSON via serde).
//!
//! Guarda as entradas salvas (enderecos fixos ou cadeias de ponteiro, tipo,
//! descricao, freeze, valor) e o script do Auto Assembler atual, para que o
//! trabalho sobreviva entre sessoes.

use serde::{Deserialize, Serialize};

use crate::pointer::PtrPath;
use crate::value::ValueType;

/// Versao do formato. Incrementar em mudancas incompativeis.
const FORMAT_VERSION: u32 = 1;

/// Uma entrada serializavel da cheat table (espelha `SavedEntry` do main).
#[derive(Serialize, Deserialize)]
pub struct TableEntry {
    pub address: u64,
    pub value_type: ValueType,
    #[serde(default)]
    pub desc: String,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub edit_text: String,
    #[serde(default)]
    pub pointer: Option<PtrPath>,
    #[serde(default)]
    pub str_len: usize,
}

/// Conteudo completo de um arquivo `.qct`.
#[derive(Serialize, Deserialize)]
pub struct TableFile {
    pub version: u32,
    #[serde(default)]
    pub process_hint: String,
    #[serde(default)]
    pub aa_script: String,
    #[serde(default)]
    pub entries: Vec<TableEntry>,
}

impl TableFile {
    pub fn new(process_hint: String, aa_script: String, entries: Vec<TableEntry>) -> Self {
        Self {
            version: FORMAT_VERSION,
            process_hint,
            aa_script,
            entries,
        }
    }
}

/// Salva a tabela em `path` (JSON identado).
pub fn save(path: &std::path::Path, file: &TableFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(file).map_err(|e| format!("serializar: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("escrever {}: {e}", path.display()))
}

/// Carrega a tabela de `path`.
pub fn load(path: &std::path::Path) -> Result<TableFile, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("ler {}: {e}", path.display()))?;
    let file: TableFile = serde_json::from_str(&data).map_err(|e| format!("formato invalido: {e}"))?;
    if file.version > FORMAT_VERSION {
        return Err(format!(
            "arquivo da versao {} e mais novo que o suportado ({FORMAT_VERSION}).",
            file.version
        ));
    }
    Ok(file)
}
