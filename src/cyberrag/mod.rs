//! Explicação de achado com recuperação aumentada e validação por ontologia
//! (reimplementação própria inspirada no CyberRAG; créditos e adaptações em
//! docs/cyberrag.md).

#![allow(dead_code)] // consumido pela fase de explicação, no PR seguinte

pub mod corpus;
pub mod ontology;
pub mod retriever;
pub mod service;

use corpus::Corpus;
use ontology::Ontology;

/// O artigo usa k=1; aqui 3 documentos dão contexto sem virar ruído.
pub const DEFAULT_TOP_K: usize = 3;

/// Casa consulta, rótulos e corpus independente de grafia.
pub(crate) fn fold_accents(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'è' | 'é' | 'ê' | 'ë' => 'e',
            'ì' | 'í' | 'î' | 'ï' => 'i',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
            'ù' | 'ú' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            other => other,
        })
        .collect()
}

/// Lista vazia significa consistente. Contrato dos dados: toda fraqueza precisa
/// de 2 mitigações, 1 ativo exposto e 1 técnica declarada.
pub fn inconsistencies(corpus: &Corpus, ontology: &Ontology) -> Vec<String> {
    let mut problems = Vec::new();
    let weaknesses = ontology.weakness_ids();

    for entry in corpus.entries() {
        if !weaknesses.contains(entry.classe.as_str()) {
            problems.push(format!(
                "a classe \"{}\" da entrada \"{}\" não é uma fraqueza da ontologia",
                entry.classe, entry.id
            ));
        }
    }

    for weakness in &weaknesses {
        let count = |relation: &str| {
            ontology
                .triples_of(relation)
                .iter()
                .filter(|(subject, _)| subject == weakness)
                .count()
        };
        if count("mitigada_por") < 2 {
            problems.push(format!(
                "a fraqueza \"{weakness}\" tem menos de 2 mitigações declaradas"
            ));
        }
        if count("expoe") < 1 {
            problems.push(format!("a fraqueza \"{weakness}\" não expõe nenhum ativo"));
        }
        if count("explorada_por") < 1 {
            problems.push(format!(
                "a fraqueza \"{weakness}\" não tem técnica de exploração declarada"
            ));
        }
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_assets_load_and_are_consistent() {
        let corpus = Corpus::embedded();
        let ontology = Ontology::embedded();

        assert!(
            corpus.len() >= 20,
            "o corpus embutido perdeu entradas: {}",
            corpus.len()
        );
        assert!(
            ontology.triple_count() >= 80,
            "a ontologia embutida perdeu triplas: {}",
            ontology.triple_count()
        );
        let problems = inconsistencies(&corpus, &ontology);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    /// O corpus, a ontologia e o índice embutidos são compartilhados pelo
    /// processo: o clique da explicação não pode reprocessar o TOML.
    #[test]
    fn the_embedded_assets_are_shared_instances() {
        assert!(
            std::ptr::eq(Corpus::shared(), Corpus::shared()),
            "o corpus precisa ser o mesmo objeto em todo o processo"
        );
        assert!(
            std::ptr::eq(Ontology::shared(), Ontology::shared()),
            "a ontologia precisa ser o mesmo objeto em todo o processo"
        );
        assert!(
            std::ptr::eq(
                crate::cyberrag::retriever::LexicalRetriever::shared(),
                crate::cyberrag::retriever::LexicalRetriever::shared()
            ),
            "o índice BM25 do corpus embutido precisa ser construído uma única vez"
        );
        assert_eq!(
            crate::cyberrag::retriever::LexicalRetriever::shared().len(),
            Corpus::shared().len(),
            "o índice precisa cobrir todas as entradas do corpus embutido"
        );
        assert_eq!(
            Corpus::embedded().len(),
            Corpus::shared().len(),
            "a cópia do corpus embutido mantém o conteúdo"
        );
    }

    #[test]
    fn an_uncovered_class_is_reported_as_inconsistency() {
        let corpus = Corpus::from_toml(include_str!("../../tests/fixtures/cyberrag/corpus.toml"))
            .expect("fixture válida");
        let ontology =
            Ontology::from_toml(include_str!("../../tests/fixtures/cyberrag/ontology.toml"))
                .expect("fixture válida");

        let with_unknown = Corpus::from_toml(
            r#"
[[entradas]]
id = "classe_nova"
classe = "classe_nova"
titulo = "t"
descricao = "d"
padrao_seguro = "p"
"#,
        )
        .expect("TOML válido");

        let problems = inconsistencies(&with_unknown, &ontology);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("classe_nova"), "{problems:#?}");
        assert!(inconsistencies(&corpus, &ontology).is_empty());
    }
}
