//! Recuperação no corpus do agente de explicação.
//!
//! O padrão é a busca lexical BM25, que roda offline e é determinística — a
//! divergência do Contriever do artigo é registrada em `docs/cyberrag.md`. O
//! trait `Retriever` é a costura para o caminho de embeddings via provedor.

use crate::cyberrag::corpus::{searchable_text, Corpus};
use crate::domain::vulnerability::Vulnerability;
use std::collections::HashMap;

/// Um documento recuperado, com a pontuação que o ordenou.
#[derive(Debug, Clone, PartialEq)]
pub struct Retrieved {
    pub id: String,
    pub score: f64,
}

/// Recupera os `k` documentos mais relevantes para uma consulta.
pub trait Retriever {
    fn retrieve(&self, query: &str, k: usize) -> Vec<Retrieved>;
}

/// Constantes clássicas do BM25 (`k1` saturação de frequência, `b` norma de
/// comprimento).
const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;

/// Teto de caracteres da consulta montada a partir de um achado.
pub const DEFAULT_QUERY_MAX_CHARS: usize = 2_000;

struct DocIndex {
    id: String,
    term_frequency: HashMap<String, usize>,
    length: usize,
}

/// Índice BM25 em memória, montado uma vez a partir do corpus.
pub struct LexicalRetriever {
    docs: Vec<DocIndex>,
    document_frequency: HashMap<String, usize>,
    average_length: f64,
}

impl LexicalRetriever {
    pub fn build(corpus: &Corpus) -> Self {
        let mut docs = Vec::with_capacity(corpus.len());
        let mut document_frequency: HashMap<String, usize> = HashMap::new();
        let mut total_length = 0usize;

        for entry in corpus.entries() {
            let tokens = tokenize(&searchable_text(entry));
            let mut term_frequency: HashMap<String, usize> = HashMap::new();
            for token in &tokens {
                *term_frequency.entry(token.clone()).or_default() += 1;
            }
            for term in term_frequency.keys() {
                *document_frequency.entry(term.clone()).or_default() += 1;
            }
            total_length += tokens.len();
            docs.push(DocIndex {
                id: entry.id.clone(),
                term_frequency,
                length: tokens.len(),
            });
        }

        let average_length = if docs.is_empty() {
            0.0
        } else {
            total_length as f64 / docs.len() as f64
        };

        Self {
            docs,
            document_frequency,
            average_length,
        }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }
}

impl Retriever for LexicalRetriever {
    fn retrieve(&self, query: &str, k: usize) -> Vec<Retrieved> {
        if k == 0 || self.docs.is_empty() || self.average_length == 0.0 {
            return Vec::new();
        }
        let terms = unique(query);

        let mut scored: Vec<Retrieved> = self
            .docs
            .iter()
            .filter_map(|doc| {
                let score = terms
                    .iter()
                    .map(|term| term_score(self, doc, term))
                    .sum::<f64>();
                (score > 0.0).then(|| Retrieved {
                    id: doc.id.clone(),
                    score,
                })
            })
            .collect();

        // Pontuação não tem ordem total; o desempate por id mantém a busca
        // determinística entre execuções com o mesmo corpus.
        scored.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.id.cmp(&right.id))
        });
        scored.truncate(k);
        scored
    }
}

fn term_score(index: &LexicalRetriever, doc: &DocIndex, term: &str) -> f64 {
    let Some(frequency) = doc.term_frequency.get(term) else {
        return 0.0;
    };
    let document_frequency = index
        .document_frequency
        .get(term)
        .copied()
        .unwrap_or_default() as f64;
    let total = index.docs.len() as f64;
    let idf = (1.0 + (total - document_frequency + 0.5) / (document_frequency + 0.5)).ln();
    let frequency = *frequency as f64;
    let length_norm = BM25_K1 * (1.0 - BM25_B + BM25_B * doc.length as f64 / index.average_length);
    idf * frequency * (BM25_K1 + 1.0) / (frequency + length_norm)
}

/// Monta a consulta a partir de um achado e, quando houver, do trecho real do
/// usuário: é o trecho que aproxima a busca do exemplo que casa com o código.
pub fn query_for_finding(
    finding: &Vulnerability,
    snippet: Option<&str>,
    max_chars: usize,
) -> String {
    let mut query = format!(
        "{} {} {} {}",
        finding.title, finding.description, finding.evidence, finding.tool
    );
    if let Some(snippet) = snippet {
        query.push(' ');
        query.push_str(snippet);
    }
    truncate_chars(&query, max_chars)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn tokenize(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.chars().count() >= 2)
        .map(|token| crate::cyberrag::fold_accents(&token.to_lowercase()))
        .collect()
}

fn unique(query: &str) -> Vec<String> {
    let mut terms = tokenize(query);
    terms.sort();
    terms.dedup();
    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    fn fixture_retriever() -> LexicalRetriever {
        LexicalRetriever::build(
            &Corpus::from_toml(include_str!("../../tests/fixtures/cyberrag/corpus.toml"))
                .expect("fixture válida"),
        )
    }

    fn finding(title: &str, description: &str, evidence: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
            tool: "code-audit".to_string(),
            severity: Severity::High,
            source: FindingSource::CodeAudit,
            target: "app.py".to_string(),
            detected_at: "2026-10-14T00:00:00Z".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn ranks_the_expected_class_first_for_a_code_query() {
        let retriever = fixture_retriever();
        let query =
            "SELECT * FROM users WHERE name = '\" + user + \"' cursor.execute concatenation";
        let results = retriever.retrieve(query, 2);

        assert_eq!(
            results.first().map(|item| item.id.as_str()),
            Some("injecao_sql")
        );
    }

    #[test]
    fn accent_insensitive_matching_works() {
        let retriever = fixture_retriever();
        let results = retriever.retrieve("injeção de SQL", 1);

        assert_eq!(
            results.first().map(|item| item.id.as_str()),
            Some("injecao_sql")
        );
    }

    #[test]
    fn the_code_snippet_steers_the_search_towards_the_matching_example() {
        let retriever = fixture_retriever();
        let finding = finding(
            "Achado genérico",
            "Entrada do usuário concatenada na consulta",
            "matched-at: /api",
        );
        let query = query_for_finding(
            &finding,
            Some("db.cursor.execute(\"SELECT * FROM users WHERE name = '\" + user + \"'\")"),
            DEFAULT_QUERY_MAX_CHARS,
        );
        let results = retriever.retrieve(&query, 1);

        assert_eq!(
            results.first().map(|item| item.id.as_str()),
            Some("injecao_sql")
        );
    }

    #[test]
    fn the_query_is_truncated_at_the_configured_ceiling() {
        let finding = finding("t", "d", "e");
        let query = query_for_finding(&finding, Some(&"x".repeat(10_000)), 100);

        assert_eq!(query.chars().count(), 100);
    }

    #[test]
    fn an_empty_or_unrelated_query_returns_nothing() {
        let retriever = fixture_retriever();

        assert!(retriever.retrieve("", 3).is_empty());
        assert!(retriever.retrieve("zzzzzzz", 3).is_empty());
    }

    #[test]
    fn k_limits_the_result_set_and_the_order_is_deterministic() {
        let retriever = fixture_retriever();
        // "python" aparece nos dois exemplos; a segunda chamada precisa
        // devolver exatamente a mesma ordem (desempate estável).
        let first = retriever.retrieve("python", 10);
        let second = retriever.retrieve("python", 10);

        assert!(!first.is_empty());
        assert!(first.len() <= 2);
        assert_eq!(first, second, "a mesma consulta precisa dar a mesma ordem");
        assert_eq!(retriever.retrieve("python", 1).len(), 1);
        assert!(retriever.retrieve("python", 0).is_empty());
    }
}
