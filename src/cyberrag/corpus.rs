//! Corpus de conhecimento de vulnerabilidade do agente de explicação.
//!
//! Autoral e embutido no binário; nada é carregado da rede.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CodeExample {
    pub linguagem: String,
    pub vulneravel: String,
    pub corrigido: String,
}

/// Guia de um cabeçalho específico dentro da classe genérica de cabeçalhos.
///
/// A classe agregada dizia que "cabeçalho ausente" mitiga XSS e clickjacking,
/// o que fazia o modelo atribuir o efeito errado a Permissions-Policy, COOP ou
/// HSTS. O guia separa efeito próprio, o que o cabeçalho não faz, valor e
/// verificação.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HeaderGuide {
    pub cabecalho: String,
    pub efeito: String,
    pub nao_mitiga: String,
    pub valor: String,
    pub verificacao: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CorpusEntry {
    pub id: String,
    pub classe: String,
    #[serde(default)]
    pub cwe: String,
    pub titulo: String,
    pub descricao: String,
    pub padrao_seguro: String,
    #[serde(default)]
    pub exemplos: Vec<CodeExample>,
    #[serde(default)]
    pub referencias: Vec<String>,
    #[serde(default)]
    pub cabecalhos: Vec<HeaderGuide>,
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    entradas: Vec<CorpusEntry>,
}

#[derive(Debug, Clone)]
pub struct Corpus {
    entries: Vec<CorpusEntry>,
    by_id: BTreeMap<String, usize>,
}

impl Corpus {
    /// Corpus embutido, analisado uma única vez por processo.
    ///
    /// O TOML é a fonte do índice BM25 e da montagem do prompt: reprocessá-lo a
    /// cada clique de "Explicar (IA)" custava dezenas de milissegundos.
    pub fn shared() -> &'static Corpus {
        static SHARED: OnceLock<Corpus> = OnceLock::new();
        SHARED.get_or_init(|| {
            Self::from_toml(include_str!("../../assets/cyberrag/corpus.toml"))
                .expect("o corpus embutido precisa ser um TOML válido")
        })
    }

    /// Cópia própria do corpus embutido.
    pub fn embedded() -> Self {
        Self::shared().clone()
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Falha ao ler o corpus em {path:?}"))?;
        Self::from_toml(&text)
    }

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

    pub fn header_guide(&self, concept: &str, header: &str) -> Option<&HeaderGuide> {
        let entry = self.get(concept)?;
        entry
            .cabecalhos
            .iter()
            .find(|guide| guide.cabecalho.eq_ignore_ascii_case(header.trim()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Indexa também o código dos exemplos: o trecho real do usuário precisa
/// aproximar a busca do exemplo que será exibido ao lado da explicação.
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
