//! Corpus de conhecimento de vulnerabilidade do agente de explicação.
//!
//! Cada entrada descreve uma classe de fraqueza (CWE), o padrão seguro de
//! correção e exemplos de código vulnerável/seguro por linguagem. O corpus é
//! autoral e embutido no binário; nada é carregado da rede.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Exemplo de código de uma linguagem para uma classe de fraqueza.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CodeExample {
    pub linguagem: String,
    pub vulneravel: String,
    pub corrigido: String,
}

/// Uma entrada do corpus, ancorável pela classe de fraqueza.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CorpusEntry {
    /// Identificador da entrada (igual à classe por enquanto).
    pub id: String,
    /// Classe de fraqueza na ontologia (`injecao_sql`, `xss`, ...).
    pub classe: String,
    /// Referência CWE da classe, quando houver.
    #[serde(default)]
    pub cwe: String,
    pub titulo: String,
    pub descricao: String,
    pub padrao_seguro: String,
    #[serde(default)]
    pub exemplos: Vec<CodeExample>,
    #[serde(default)]
    pub referencias: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    entradas: Vec<CorpusEntry>,
}

/// Corpus carregado e indexado por id.
#[derive(Debug, Clone)]
pub struct Corpus {
    entries: Vec<CorpusEntry>,
    by_id: BTreeMap<String, usize>,
}

impl Corpus {
    /// Carrega o corpus do TOML embutido no binário.
    ///
    /// O `expect` é deliberado: o arquivo é parte do binário e os testes de
    /// consistência (idioma, schema e ontologia) o validam na suíte.
    pub fn embedded() -> Self {
        Self::from_toml(include_str!("../../assets/cyberrag/corpus.toml"))
            .expect("o corpus embutido precisa ser um TOML válido")
    }

    /// Carrega o corpus de um arquivo do disco; usado para override local.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Falha ao ler o corpus em {path:?}"))?;
        Self::from_toml(&text)
    }

    /// Interpreta o TOML e valida os invariantes de forma.
    pub fn from_toml(text: &str) -> Result<Self> {
        let file: CorpusFile = toml::from_str(text).context("TOML de corpus inválido")?;
        if file.entradas.is_empty() {
            bail!("o corpus não pode ser vazio");
        }

        let mut by_id = BTreeMap::new();
        for (index, entry) in file.entradas.iter().enumerate() {
            for (field, value) in [
                ("id", &entry.id),
                ("classe", &entry.classe),
                ("titulo", &entry.titulo),
                ("descricao", &entry.descricao),
                ("padrao_seguro", &entry.padrao_seguro),
            ] {
                if value.trim().is_empty() {
                    bail!("a entrada \"{}\" tem o campo \"{field}\" vazio", entry.id);
                }
            }
            for example in &entry.exemplos {
                if example.linguagem.trim().is_empty()
                    || example.vulneravel.trim().is_empty()
                    || example.corrigido.trim().is_empty()
                {
                    bail!(
                        "a entrada \"{}\" tem exemplo de código incompleto ({})",
                        entry.id,
                        example.linguagem
                    );
                }
            }
            if by_id.insert(entry.id.clone(), index).is_some() {
                bail!("id de corpus duplicado: \"{}\"", entry.id);
            }
        }

        Ok(Self {
            entries: file.entradas,
            by_id,
        })
    }

    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    pub fn get(&self, id: &str) -> Option<&CorpusEntry> {
        self.by_id.get(id).map(|index| &self.entries[*index])
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Texto indexado para busca: título, descrição, correção, CWE e exemplos.
///
/// O código dos exemplos entra de propósito: um trecho real do usuário que
/// contenha `cursor.execute` ou `subprocess` precisa aproximar a busca da
/// classe certa, e é o próprio exemplo que será exibido ao lado da explicação.
pub fn searchable_text(entry: &CorpusEntry) -> String {
    let mut text = format!(
        "{} {} {} {} {}",
        entry.titulo, entry.descricao, entry.padrao_seguro, entry.cwe, entry.classe
    );
    for example in &entry.exemplos {
        text.push(' ');
        text.push_str(&example.linguagem);
        text.push(' ');
        text.push_str(&example.vulneravel);
        text.push(' ');
        text.push_str(&example.corrigido);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/cyberrag/corpus.toml");

    #[test]
    fn loads_the_fixture_and_indexes_by_id() {
        let corpus = Corpus::from_toml(FIXTURE).expect("fixture válida");

        assert_eq!(corpus.len(), 2);
        let entry = corpus.get("injecao_sql").expect("entrada presente");
        assert_eq!(entry.cwe, "CWE-89");
        assert_eq!(entry.exemplos.len(), 1);
        assert!(searchable_text(entry).contains("CWE-89"));
        assert!(searchable_text(entry).contains("cursor.execute"));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let text = r#"
[[entradas]]
id = "x"
classe = "x"
titulo = "t"
descricao = "d"
padrao_seguro = "p"

[[entradas]]
id = "x"
classe = "x"
titulo = "t2"
descricao = "d2"
padrao_seguro = "p2"
"#;
        let error = Corpus::from_toml(text).unwrap_err().to_string();
        assert!(error.contains("duplicado"), "{error}");
    }

    #[test]
    fn rejects_an_entry_with_an_incomplete_code_example() {
        let text = r#"
[[entradas]]
id = "x"
classe = "x"
titulo = "t"
descricao = "d"
padrao_seguro = "p"

[[entradas.exemplos]]
linguagem = "python"
vulneravel = "algo"
corrigido = "  "
"#;
        let error = Corpus::from_toml(text).unwrap_err().to_string();
        assert!(error.contains("exemplo de código incompleto"), "{error}");
    }

    #[test]
    fn rejects_an_empty_corpus() {
        let error = Corpus::from_toml("entradas = []").unwrap_err().to_string();
        assert!(error.contains("não pode ser vazio"), "{error}");
    }
}
