//! Explicação de achado com recuperação aumentada e validação por ontologia.
//!
//! Desenho derivado do artigo "Ontology-Aware RAG for Improved Question-Answering
//! in Cybersecurity Education" (Zhao et al., IEEE BigData 2025, DOI
//! 10.1109/BigData66926.2025.11401740, arXiv:2412.14191): recuperar contexto,
//! gerar com o contexto e validar a resposta contra uma ontologia de segurança.
//! A implementação é própria (o artigo é CC BY 4.0; o repositório de referência
//! não tem licença e nada dele é usado) e troca o juiz-LLM do artigo por
//! validação simbólica determinística — adaptação registrada em docs/cyberrag.md.

#![allow(dead_code)] // consumido pela fase de explicação, no PR seguinte

pub mod corpus;
pub mod ontology;
pub mod retriever;

use corpus::Corpus;
use ontology::Ontology;

/// Top-k padrão da recuperação. O artigo usa k=1; aqui os documentos são
/// unidades de conhecimento independentes e 3 dão contexto sem virar ruído.
pub const DEFAULT_TOP_K: usize = 3;

/// Remove acentos para que consulta, rótulos e corpus casem independente de
/// grafia.
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

/// Verifica a consistência entre o corpus e a ontologia.
///
/// Lista vazia significa consistente. As exigências abaixo são o contrato dos
/// dados: uma fraqueza sem mitigação ou sem técnica declarada não sustenta a
/// validação das explicações que vão citá-las.
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

    #[test]
    fn an_uncovered_class_is_reported_as_inconsistency() {
        let corpus = Corpus::from_toml(include_str!("../../tests/fixtures/cyberrag/corpus.toml"))
            .expect("fixture válida");
        let ontology =
            Ontology::from_toml(include_str!("../../tests/fixtures/cyberrag/ontology.toml"))
                .expect("fixture válida");

        // A fixture de corpus cobre as mesmas classes; uma entrada sintética com
        // classe desconhecida precisa ser apontada.
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

        // E o par de fixtures precisa ser consistente de verdade.
        assert!(inconsistencies(&corpus, &ontology).is_empty());
    }
}
