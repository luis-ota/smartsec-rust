//! Enriquecimento CVE/NVD dos achados já correlacionados (issue #19, REQ11).
//!
//! ## Ordem das operações
//!
//! 1. Os achados saem dos parsers e passam pela [correlação][correlate], que
//!    consolida o que é o mesmo problema e preserva todas as origens.
//! 2. Só então o enriquecimento é consultado: um CVE aforementioned por
//!    qualquer origem do grupo enriquece o grupo inteiro.
//! 3. Por fim a divergência entre a severidade do scanner e a da NVD é
//!    registrada, sem alterar nenhuma das duas.
//!
//! ## A indisponibilidade não impede o relatório base
//!
//! Se a NVD estiver fora do ar, o enrichment devolve os achados **inalterados**
//! e um [`NvdReport`] com a causa em pt-BR. Não há `unwrap`, `expect` nem
//! `panic` neste módulo: um `unwrap()` aqui reprovaria a issue.
//!
//! ## Limite de taxa
//!
//! Os identificadores são consultados **sequencialmente**, com espera do
//! intervalo mínimo entre eles. É o que respeita o limite publicado da NVD
//! ([5 req/30 s][rate] sem chave, [50 req/30 s][rate] com chave) sem depender
//! de reentrada da API.
//!
//! [rate]: https://nvd.nist.gov/developers/vulnerabilities

use crate::domain::enrichment::CveEnrichment;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::correlation::{annotate_nvd_divergence, correlate, CorrelationReport};
use crate::orchestrator::nvd::{NvdClient, NvdOutcome, NvdReport};

/// Resultado consolidado de correlacionar e enriquecer uma varredura.
///
/// Serializável para que o resumo entre no log estruturado de auditoria.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EnrichmentSummary {
    /// Resumo da deduplicação.
    #[serde(default)]
    pub correlation: CorrelationReport,
    /// Resumo da consulta à NVD.
    #[serde(default)]
    pub nvd: NvdReport,
}

impl EnrichmentSummary {
    /// `true` quando algo impede o enriquecimento e precisa ficar visível.
    pub fn is_degraded(&self) -> bool {
        self.nvd.is_degraded()
    }

    /// Linhas em pt-BR para a TUI, o modo headless e o relatório.
    pub fn lines_pt_br(&self) -> Vec<String> {
        let mut lines = vec![self.correlation.summary_pt_br()];
        if self.nvd.consulted > 0 || self.nvd.is_degraded() {
            lines.push(self.nvd.summary_pt_br());
        }
        lines
    }
}

/// Correlaciona os achados e enriquece cada grupo com os dados da NVD.
///
/// Os achados de entrada não são perdidos: a quantidade consolidada é igual ou
/// menor à entrada, e cada grupo mantém todas as origens em
/// [`crate::domain::enrichment::FindingOrigin`].
pub async fn correlate_and_enrich(
    findings: Vec<Vulnerability>,
    client: Option<&NvdClient>,
) -> (Vec<Vulnerability>, EnrichmentSummary) {
    let (mut correlated, correlation) = correlate(findings);
    let mut report = NvdReport::default();

    let Some(client) = client else {
        report.unavailable_reasons.push(
            "o cliente da NVD não pôde ser inicializado; o enriquecimento foi pulado".to_string(),
        );
        let summary = EnrichmentSummary {
            correlation,
            nvd: report,
        };
        return (correlated, summary);
    };

    // Coleta os identificadores distintos de todo o grupo, na ordem em que
    // aparecem, para que a consulta seja determinística entre execuções.
    let mut pending: Vec<String> = Vec::new();
    for finding in &correlated {
        for cve in group_cve_ids(finding) {
            if !pending.contains(&cve) {
                pending.push(cve);
            }
        }
    }
    report.consulted = pending.len();

    // Um mesmo identificador citado por vários achados vira uma única consulta.
    for (index, cve_id) in pending.iter().enumerate() {
        // Respeita o intervalo mínimo publicado pela NVD entre requisições.
        if index > 0 {
            tokio::time::sleep(client.min_interval()).await;
        }
        match client.lookup(cve_id).await {
            NvdOutcome::Enriched(enrichment) => {
                if enrichment.from_cache {
                    report.cached += 1;
                } else {
                    report.enriched += 1;
                }
                apply_enrichment(&mut correlated, cve_id, *enrichment);
            }
            NvdOutcome::NotFound => {
                report.not_found += 1;
            }
            NvdOutcome::Unavailable(reason) => {
                push_reason(&mut report.unavailable_reasons, reason);
            }
        }
    }

    for finding in &mut correlated {
        annotate_nvd_divergence(finding);
    }

    let summary = EnrichmentSummary {
        correlation,
        nvd: report,
    };
    (correlated, summary)
}

/// Anexa o enriquecimento a todo grupo que cita o identificador consultado.
fn apply_enrichment(findings: &mut [Vulnerability], cve_id: &str, enrichment: CveEnrichment) {
    let cve = cve_id.to_ascii_uppercase();
    for finding in findings.iter_mut() {
        if group_cve_ids(finding).contains(&cve) {
            finding.enrichment = Some(enrichment.clone());
        }
    }
}

/// Identificadores CVE que valem uma consulta, para um achado ou para o grupo.
///
/// A mesma extração da [correlação][crate::orchestrator::correlation] é
/// reutilizada: se dois achados foramconsidered o mesmo problema, a consulta
/// também é a mesma.
/// Identificadores CVE citados pelo achado e por todas as suas origens.
///
/// A extração é a mesma da [correlação][crate::orchestrator::correlation]: se
/// dois achados foram considerados o mesmo problema, a consulta também é a
/// mesma.
fn group_cve_ids(finding: &Vulnerability) -> Vec<String> {
    let mut ids = crate::orchestrator::correlation::cve_ids_of(&finding.evidence);
    for origin in &finding.origins {
        for id in crate::orchestrator::correlation::cve_ids_of(&origin.evidence) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

/// Acumula a causa de indisponibilidade sem repetir a mesma mensagem.
fn push_reason(reasons: &mut Vec<String>, reason: String) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;
    use crate::orchestrator::nvd::NvdClient;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_cache_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("smartsec-enrich-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn finding(tool: &str, severity: Severity, title: &str, evidence: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity,
            description: format!("Descrição de {title}"),
            tool: tool.to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: evidence.to_string(),
            detected_at: "2026-09-30T10:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            code_location: None,
            code_remediation: Vec::new(),
        }
    }

    fn log4shell(severity: Severity, matcher: &str) -> Vulnerability {
        finding(
            "Nuclei",
            severity,
            "Possível vulnerabilidade detectada — CVE-2021-44228",
            &format!("template: cve-2021-44228 | matcher: {matcher} | endpoint: http://alvo.local/app | host: alvo.local | url: http://alvo.local/app | tags: cve,rce"),
        )
    }

    #[tokio::test]
    async fn sem_cliente_a_varredura_segue_com_o_relatorio_base() {
        let findings = vec![log4shell(Severity::Critical, "jndi")];

        let (correlated, summary) = correlate_and_enrich(findings, None).await;

        assert_eq!(correlated.len(), 1, "o achado não pode sumir");
        assert_eq!(correlated[0].severity, Severity::Critical);
        assert!(summary.is_degraded());
        assert!(summary.nvd.summary_pt_br().contains("relatório base"));
    }

    #[tokio::test]
    async fn enriquecimento_nunca_reclassifica_a_severidade_do_scanner() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let findings = vec![log4shell(Severity::Low, "jndi")];

        let (correlated, summary) = correlate_and_enrich(findings, Some(&client)).await;

        assert_eq!(
            correlated[0].severity,
            Severity::Low,
            "o scanner é autoritativo"
        );
        match summary.nvd.enriched + summary.nvd.cached {
            0 => {
                // NVD fora do ar: a degradação precisa estar visível.
                assert!(
                    summary.is_degraded(),
                    "sem enriquecimento e sem causa é silêncio"
                );
            }
            _ => {
                let enrichment = correlated[0]
                    .enrichment
                    .as_ref()
                    .expect("o achado cita um CVE real e deve ser enriquecido");
                assert_eq!(enrichment.cve_id, "CVE-2021-44228");
                assert_eq!(enrichment.cvss_severity, Some(Severity::Critical));
                assert!(!enrichment.queried_at.is_empty());
                // A divergência precisa ficar registrada.
                let conflict = correlated[0]
                    .severity_conflict
                    .as_ref()
                    .expect("divergência entre scanner e NVD precisa ser visível");
                assert_eq!(conflict.nvd_severity, Some(Severity::Critical));
                assert!(conflict.detail.contains("Nuclei: BAIXA"));
            }
        }
    }

    #[tokio::test]
    async fn grupo_correlacionado_recebe_um_unico_enriquecimento() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let do_nuclei = log4shell(Severity::Critical, "jndi");
        let do_zap = finding(
            "ZAP",
            Severity::Low,
            "Log4Shell",
            "template: CVE-2021-44228 | matcher: baixa | endpoint: http://alvo.local/app",
        );

        let (correlated, _) = correlate_and_enrich(vec![do_nuclei, do_zap], Some(&client)).await;

        assert_eq!(correlated.len(), 1, "o mesmo CVE é o mesmo problema");
        let group = &correlated[0];
        assert_eq!(group.origins.len(), 2, "as duas origens continuam visíveis");
        assert!(group.tool.contains("Nuclei") && group.tool.contains("ZAP"));
        if group.enrichment.is_some() {
            assert_eq!(group.origins.len(), 2, "o merge não descarta origem");
        }
    }

    #[tokio::test]
    async fn achados_sem_cve_sao_conservados_sem_consulta() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let findings = vec![finding(
            "Nmap",
            Severity::Medium,
            "Porta 3000",
            "nmap porta=3000/tcp serviço=http produto=nginx versão=1.2",
        )];

        let (correlated, summary) = correlate_and_enrich(findings, Some(&client)).await;

        assert_eq!(correlated.len(), 1);
        assert_eq!(summary.nvd.consulted, 0, "não há o que consultar");
        assert!(
            !summary.is_degraded(),
            "sem consulta não há indisponibilidade"
        );
        assert!(correlated[0].enrichment.is_none());
    }

    #[tokio::test]
    async fn causa_de_indisponibilidade_fica_visivel_e_sem_duplicatas() {
        let mut reasons = Vec::new();
        push_reason(&mut reasons, "timeout".to_string());
        push_reason(&mut reasons, "timeout".to_string());
        push_reason(&mut reasons, "status 503".to_string());

        assert_eq!(reasons, vec!["timeout", "status 503"]);
    }

    #[tokio::test]
    async fn cve_com_erro_nao_apaga_nenhum_achado() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let findings = vec![
            log4shell(Severity::Critical, "jndi"),
            finding(
                "Nmap",
                Severity::Medium,
                "Porta 3000",
                "nmap porta=3000/tcp serviço=http produto=nginx versão=1.2",
            ),
        ];

        let (correlated, _) = correlate_and_enrich(findings, Some(&client)).await;

        assert_eq!(correlated.len(), 2, "nenhum achado pode ser perdido");
    }

    #[tokio::test]
    async fn linhas_em_pt_br_trazem_correlacao_e_nvd() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        let (_, summary) =
            correlate_and_enrich(vec![log4shell(Severity::Critical, "jndi")], Some(&client)).await;

        let lines = summary.lines_pt_br();
        assert!(lines[0].contains("correlação"), "{lines:?}");
        assert!(lines[1].contains("NVD"), "{lines:?}");
    }
}
