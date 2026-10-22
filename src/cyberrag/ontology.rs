//! Ontologia de segurança do agente de explicação e o validador simbólico.
//!
//! Desenho derivado do artigo "Ontology-Aware RAG for Improved Question-Answering
//! in Cybersecurity Education" (Zhao et al., IEEE BigData 2025, DOI
//! 10.1109/BigData66926.2025.11401740, arXiv:2412.14191). A validação simbólica
//! local substitui o juiz-LLM do artigo (adaptação em docs/cyberrag.md); a
//! ontologia é autoral — nada copiado do repo de referência (sem licença).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

const ENTITY_KINDS: [&str; 4] = ["fraqueza", "ativo", "mitigacao", "tecnica"];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OntologyMeta {
    pub versao: String,
    pub autor: String,
    pub data: String,
    pub escopo: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OntologyEntity {
    pub id: String,
    pub tipo: String,
    #[serde(default)]
    pub rotulos: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RelationDef {
    pub id: String,
    pub rotulo: String,
    pub descricao: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OntologyTriple {
    pub sujeito: String,
    pub relacao: String,
    pub objeto: String,
}

#[derive(Debug, Deserialize)]
struct OntologyFile {
    meta: OntologyMeta,
    entidades: Vec<OntologyEntity>,
    relacoes: Vec<RelationDef>,
    #[serde(default)]
    triplas: Vec<OntologyTriple>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyClaim {
    pub sujeito: String,
    pub relacao: String,
    pub objeto: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRejection {
    pub claim: OntologyClaim,
    pub motivo: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyVerdict {
    /// Só aprova com ≥1 afirmação e nenhuma rejeição.
    pub aprovado: bool,
    pub verificadas: usize,
    pub rejeitadas: Vec<ClaimRejection>,
}

impl OntologyVerdict {
    pub fn summary(&self) -> String {
        if self.aprovado {
            return format!(
                "validação por ontologia aprovada ({} afirmação(ões) verificada(s))",
                self.verificadas
            );
        }
        if self.verificadas == 0 && self.rejeitadas.is_empty() {
            return "validação por ontologia reprovada: a resposta não trouxe afirmações verificáveis"
                .to_string();
        }
        let motivo = self
            .rejeitadas
            .first()
            .map(|rejection| rejection.motivo.clone())
            .unwrap_or_default();
        format!(
            "validação por ontologia reprovada ({} de {} afirmação(ões)): {motivo}",
            self.rejeitadas.len(),
            self.verificadas + self.rejeitadas.len()
        )
    }
}

#[derive(Debug, Clone)]
pub struct Ontology {
    meta: OntologyMeta,
    entities: Vec<OntologyEntity>,
    relations: Vec<RelationDef>,
    triples: BTreeSet<(String, String, String)>,
    entity_by_label: BTreeMap<String, String>,
    relation_by_label: BTreeMap<String, String>,
}

impl Ontology {
    /// Ontologia embutida, analisada uma única vez por processo.
    pub fn shared() -> &'static Ontology {
        static SHARED: OnceLock<Ontology> = OnceLock::new();
        SHARED.get_or_init(|| {
            Self::from_toml(include_str!("../../assets/cyberrag/ontology.toml"))
                .expect("a ontologia embutida precisa ser um TOML válido")
        })
    }

    /// Cópia própria da ontologia embutida.
    pub fn embedded() -> Self {
        Self::shared().clone()
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Falha ao ler a ontologia em {path:?}"))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let file: OntologyFile = toml::from_str(text).context("TOML de ontologia inválido")?;

        for (field, value) in [
            ("versao", &file.meta.versao),
            ("autor", &file.meta.autor),
            ("data", &file.meta.data),
            ("escopo", &file.meta.escopo),
        ] {
            if value.trim().is_empty() {
                bail!("metadado \"{field}\" da ontologia está vazio");
            }
        }
        if file.entidades.is_empty() {
            bail!("a ontologia não pode ficar sem entidades");
        }
        if file.relacoes.is_empty() {
            bail!("a ontologia não pode ficar sem relações");
        }

        let mut entity_ids = BTreeSet::new();
        let mut entity_by_label: BTreeMap<String, String> = BTreeMap::new();
        for entity in &file.entidades {
            if entity.id.trim().is_empty() {
                bail!("entidade sem id na ontologia");
            }
            if !ENTITY_KINDS.contains(&entity.tipo.as_str()) {
                bail!(
                    "entidade \"{}\" tem tipo desconhecido \"{}\"",
                    entity.id,
                    entity.tipo
                );
            }
            if !entity_ids.insert(entity.id.clone()) {
                bail!("id de entidade duplicado: \"{}\"", entity.id);
            }
            insert_label(&mut entity_by_label, &entity.id, &entity.id)?;
            for label in &entity.rotulos {
                insert_label(&mut entity_by_label, label, &entity.id)?;
            }
        }

        let mut relation_ids = BTreeSet::new();
        let mut relation_by_label: BTreeMap<String, String> = BTreeMap::new();
        for relation in &file.relacoes {
            if !relation_ids.insert(relation.id.clone()) {
                bail!("id de relação duplicado: \"{}\"", relation.id);
            }
            insert_label(&mut relation_by_label, &relation.id, &relation.id)?;
            insert_label(&mut relation_by_label, &relation.rotulo, &relation.id)?;
        }

        let mut triples = BTreeSet::new();
        for triple in &file.triplas {
            if !entity_ids.contains(&triple.sujeito) {
                bail!(
                    "tripla referencia sujeito desconhecido: \"{}\"",
                    triple.sujeito
                );
            }
            if !entity_ids.contains(&triple.objeto) {
                bail!(
                    "tripla referencia objeto desconhecido: \"{}\"",
                    triple.objeto
                );
            }
            if !relation_ids.contains(&triple.relacao) {
                bail!(
                    "tripla referencia relação desconhecida: \"{}\"",
                    triple.relacao
                );
            }
            if !triples.insert((
                triple.sujeito.clone(),
                triple.relacao.clone(),
                triple.objeto.clone(),
            )) {
                bail!(
                    "tripla duplicada: ({}, {}, {})",
                    triple.sujeito,
                    triple.relacao,
                    triple.objeto
                );
            }
        }

        Ok(Self {
            meta: file.meta,
            entities: file.entidades,
            relations: file.relacoes,
            triples,
            entity_by_label,
            relation_by_label,
        })
    }

    pub fn meta(&self) -> &OntologyMeta {
        &self.meta
    }

    pub fn entities(&self) -> &[OntologyEntity] {
        &self.entities
    }

    pub fn relations(&self) -> &[RelationDef] {
        &self.relations
    }

    pub fn triple_count(&self) -> usize {
        self.triples.len()
    }

    pub fn weakness_ids(&self) -> BTreeSet<&str> {
        self.entities
            .iter()
            .filter(|entity| entity.tipo == "fraqueza")
            .map(|entity| entity.id.as_str())
            .collect()
    }

    pub fn resolve_entity_id(&self, value: &str) -> Option<&str> {
        self.entity_by_label
            .get(&normalize_label(value))
            .map(String::as_str)
    }

    pub fn resolve_relation_id(&self, value: &str) -> Option<&str> {
        self.relation_by_label
            .get(&normalize_label(value))
            .map(String::as_str)
    }

    pub fn triples_for_subject(&self, subject: &str) -> Vec<(String, String, String)> {
        let Some(subject) = self.resolve_entity_id(subject) else {
            return Vec::new();
        };
        self.triples
            .iter()
            .filter(|(triple_subject, _, _)| triple_subject == subject)
            .cloned()
            .collect()
    }

    pub fn triples_of(&self, relation: &str) -> Vec<(&str, &str)> {
        self.triples
            .iter()
            .filter(|(_, triple_relation, _)| triple_relation == relation)
            .map(|(subject, _, object)| (subject.as_str(), object.as_str()))
            .collect()
    }

    /// Vocabulário fechado do turno de geração: sem ele o modelo não produz
    /// afirmações verificáveis.
    pub fn vocabulary_for_prompt(&self) -> String {
        let mut vocabulary = String::from("Entidades (id · tipo · rótulos):\n");
        for entity in &self.entities {
            let labels = entity.rotulos.join(" | ");
            vocabulary.push_str(&format!("- {} · {} · {labels}\n", entity.id, entity.tipo));
        }
        vocabulary.push_str("\nRelações (id · rótulo · significado):\n");
        for relation in &self.relations {
            vocabulary.push_str(&format!(
                "- {} · {} · {}\n",
                relation.id, relation.rotulo, relation.descricao
            ));
        }
        // O modelo precisa das triplas, não só de entidades e relações.
        vocabulary
            .push_str("\nTriplas válidas (sujeito · relação · objeto) — use somente estas:\n");
        for (subject, relation, object) in &self.triples {
            vocabulary.push_str(&format!("- {subject} · {relation} · {object}\n"));
        }
        vocabulary
    }

    /// Resolução por id ou rótulo (acento-insensível). Sem tripla correspondente,
    /// a afirmação é rejeitada — plausível não basta.
    pub fn validate_claims(&self, claims: &[OntologyClaim]) -> OntologyVerdict {
        let mut rejeitadas = Vec::new();
        let mut verificadas = 0usize;

        for claim in claims {
            let subject = self.entity_by_label.get(&normalize_label(&claim.sujeito));
            let object = self.entity_by_label.get(&normalize_label(&claim.objeto));
            let relation = self.relation_by_label.get(&normalize_label(&claim.relacao));
            let motivo = match (subject, relation, object) {
                (None, _, _) => Some(format!(
                    "o conceito \"{}\" não existe na ontologia",
                    claim.sujeito
                )),
                (_, None, _) => Some(format!(
                    "a relação \"{}\" não existe na ontologia",
                    claim.relacao
                )),
                (_, _, None) => Some(format!(
                    "o conceito \"{}\" não existe na ontologia",
                    claim.objeto
                )),
                (Some(subject), Some(relation), Some(object)) => {
                    if self
                        .triples
                        .contains(&(subject.clone(), relation.clone(), object.clone()))
                    {
                        None
                    } else {
                        Some(format!(
                            "a tripla ({subject}, {relation}, {object}) não existe na ontologia"
                        ))
                    }
                }
            };
            match motivo {
                None => verificadas += 1,
                Some(motivo) => rejeitadas.push(ClaimRejection {
                    claim: claim.clone(),
                    motivo,
                }),
            }
        }

        OntologyVerdict {
            aprovado: !claims.is_empty() && rejeitadas.is_empty(),
            verificadas,
            rejeitadas,
        }
    }
}

fn insert_label(index: &mut BTreeMap<String, String>, label: &str, id: &str) -> Result<()> {
    let normalized = normalize_label(label);
    if normalized.is_empty() {
        return Ok(());
    }
    match index.get(&normalized) {
        Some(existing) if existing != id => {
            bail!("o rótulo \"{label}\" aponta para \"{existing}\" e para \"{id}\"")
        }
        _ => {
            index.insert(normalized, id.to_string());
            Ok(())
        }
    }
}

pub(crate) fn normalize_label(value: &str) -> String {
    let folded = crate::cyberrag::fold_accents(&value.to_lowercase());
    folded
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|character: char| !character.is_alphanumeric())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/cyberrag/ontology.toml");

    fn fixture() -> Ontology {
        Ontology::from_toml(FIXTURE).expect("fixture válida")
    }

    fn claim(subject: &str, relation: &str, object: &str) -> OntologyClaim {
        OntologyClaim {
            sujeito: subject.to_string(),
            relacao: relation.to_string(),
            objeto: object.to_string(),
        }
    }

    #[test]
    fn loads_the_fixture_with_entities_relations_and_triples() {
        let ontology = fixture();

        assert_eq!(ontology.meta().versao, "0.0.0-teste");
        assert_eq!(ontology.entities().len(), 10);
        assert_eq!(ontology.relations().len(), 3);
        assert_eq!(ontology.triple_count(), 8);
    }

    #[test]
    fn accepts_a_triple_written_with_labels_and_accents() {
        let ontology = fixture();
        let verdict = ontology.validate_claims(&[
            claim("Injeção de SQL", "mitigada por", "consulta parametrizada"),
            claim("injecao_sql", "expoe", "banco de dados"),
        ]);

        assert!(verdict.aprovado, "{verdict:?}");
        assert_eq!(verdict.verificadas, 2);
        assert!(verdict.rejeitadas.is_empty());
    }

    #[test]
    fn rejects_a_claim_with_an_unknown_concept() {
        let ontology = fixture();
        let verdict = ontology.validate_claims(&[claim(
            "injeção de SQL",
            "mitigada_por",
            "cache distribuído",
        )]);

        assert!(!verdict.aprovado);
        assert_eq!(verdict.rejeitadas.len(), 1);
        assert!(
            verdict.rejeitadas[0]
                .motivo
                .contains("não existe na ontologia"),
            "{:?}",
            verdict.rejeitadas
        );
    }

    #[test]
    fn rejects_a_claim_with_an_unknown_relation() {
        let ontology = fixture();
        let verdict = ontology.validate_claims(&[claim(
            "injeção de SQL",
            "causada_por",
            "consulta parametrizada",
        )]);

        assert!(!verdict.aprovado);
        assert!(
            verdict.rejeitadas[0].motivo.contains("relação"),
            "{:?}",
            verdict.rejeitadas
        );
    }

    #[test]
    fn rejects_a_plausible_but_undeclared_triple() {
        let ontology = fixture();
        // As duas entidades existem, mas a tripla não foi declarada.
        let verdict = ontology.validate_claims(&[claim(
            "credencial_hardcoded",
            "mitigada_por",
            "consulta parametrizada",
        )]);

        assert!(!verdict.aprovado);
        assert!(
            verdict.rejeitadas[0]
                .motivo
                .contains("não existe na ontologia"),
            "{:?}",
            verdict.rejeitadas
        );
    }

    #[test]
    fn an_empty_claim_list_is_never_approved() {
        let verdict = fixture().validate_claims(&[]);

        assert!(!verdict.aprovado);
        assert!(verdict
            .summary()
            .contains("não trouxe afirmações verificáveis"));
    }

    #[test]
    fn summary_of_a_rejection_names_the_first_reason() {
        let ontology = fixture();
        let verdict = ontology.validate_claims(&[
            claim("injecao_sql", "expoe", "banco_de_dados"),
            // As duas entidades existem, mas esta tripla não foi declarada.
            claim("injecao_sql", "expoe", "codigo_fonte"),
        ]);

        let summary = verdict.summary();
        assert!(summary.contains("reprovada"), "{summary}");
        assert!(summary.contains("1 de 2"), "{summary}");
        assert!(
            summary.contains("(injecao_sql, expoe, codigo_fonte)"),
            "{summary}"
        );
    }

    #[test]
    fn rejects_a_triple_with_an_unknown_object() {
        let text = r#"
[meta]
versao = "1"
autor = "a"
data = "d"
escopo = "e"

[[entidades]]
id = "a"
tipo = "fraqueza"
rotulos = []

[[entidades]]
id = "b"
tipo = "ativo"
rotulos = []

[[relacoes]]
id = "r"
rotulo = "r"
descricao = "x"

[[triplas]]
sujeito = "a"
relacao = "r"
objeto = "inexistente"
"#;
        let error = Ontology::from_toml(text).unwrap_err().to_string();
        assert!(error.contains("objeto desconhecido"), "{error}");
    }

    #[test]
    fn rejects_a_label_pointing_to_two_entities() {
        let text = r#"
[meta]
versao = "1"
autor = "a"
data = "d"
escopo = "e"

[[entidades]]
id = "a"
tipo = "fraqueza"
rotulos = ["compartilhado"]

[[entidades]]
id = "b"
tipo = "ativo"
rotulos = ["compartilhado"]

[[relacoes]]
id = "r"
rotulo = "r"
descricao = "x"
"#;
        let error = Ontology::from_toml(text).unwrap_err().to_string();
        assert!(error.contains("aponta para"), "{error}");
    }
}
