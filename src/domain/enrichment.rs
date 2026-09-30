//! Contexto externo e multi-origem anexado a um achado.
//!
//! These types complete the finding contract of REQ11/REQ12. They are
//! deliberately additive: every field has a serde default so that audit logs
//! persisted before issue #19 keep deserializing.
//!
//! Regra central (TCC_SPEC.md §7): a severidade do scanner é autoritativa.
//! O enriquecimento NVD **acrescenta** contexto e **nunca** reclassifica o
//! achado. Divergências são preservadas, não sobrescritas.

use crate::domain::Severity;
use serde::{Deserialize, Serialize};

/// Proveniência preservada de cada scanner que reportou o mesmo problema.
///
/// A correlação agrega, nunca descarta: cada evidência, ferramenta e
/// severidade original continua acessível mesmo depois do merge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingOrigin {
    /// Ferramenta que reportou a origem (Nuclei, Nikto, Nmap, …).
    pub tool: String,
    /// Severidade **desta** origem, como classificada pelo próprio scanner.
    pub severity: Severity,
    /// Evidência mínima e sanitizada produzida por esta origem.
    pub evidence: String,
    /// Timestamp ISO-8601 do registro original.
    pub detected_at: String,
}

impl FindingOrigin {
    pub fn from_finding(finding: &crate::domain::vulnerability::Vulnerability) -> Self {
        Self {
            tool: crate::utils::redaction::sanitize_text(&finding.tool),
            severity: finding.severity,
            evidence: crate::utils::redaction::sanitize_text(&finding.evidence),
            detected_at: finding.detected_at.clone(),
        }
    }

    /// Aplica a sanitização a uma origem que veio de fora — por exemplo de um
    /// log já desserializado. Sem isso, uma origem persistida antes da
    /// sanitização poderia reintroduzir credencial no relatório.
    pub fn sanitized(&self) -> Self {
        Self {
            tool: crate::utils::redaction::sanitize_text(&self.tool),
            severity: self.severity,
            evidence: crate::utils::redaction::sanitize_text(&self.evidence),
            detected_at: crate::utils::redaction::sanitize_text(&self.detected_at),
        }
    }
}

/// Contexto consultado na NVD (API v2) para um identificador CVE.
///
/// A `queried_at` é obrigatória: dado de terceiro envelhece e o relatório
/// precisa declarar quando a informação foi obtida.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CveEnrichment {
    /// Identificador consultado, normalizado em maiúsculas (CVE-YYYY-NNNN).
    pub cve_id: String,
    /// Score base da métrica CVSS preferencial (4.0 → 3.1 → 3.0 → 2.0).
    pub cvss_base_score: Option<f64>,
    /// Vetor CVSS completo, ex.: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/...`.
    pub cvss_vector: Option<String>,
    /// Severidade declarada pela NVD para o score acima.
    pub cvss_severity: Option<Severity>,
    /// Versão da métrica CVSS usada (`4.0`, `3.1`, `3.0`, `2.0`).
    pub cvss_version: Option<String>,
    /// Referência pública escolhida na resposta da NVD, sanitizada.
    pub reference: Option<String>,
    /// Data da consulta em ISO-8601 (UTC).
    pub queried_at: String,
    /// `true` quando a resposta veio do cache local dentro do TTL.
    pub from_cache: bool,
}

impl CveEnrichment {
    /// Line única para relatório e tela, em pt-BR, sem corpo HTTP.
    pub fn summary_pt_br(&self) -> String {
        let score = self
            .cvss_base_score
            .map(|score| format!("{score:.1}"))
            .unwrap_or_else(|| "não pontuado".to_string());
        let severity = self
            .cvss_severity
            .map(|severity| severity.label_pt_br().to_string())
            .unwrap_or_else(|| "NÃO INFORMADA".to_string());
        let cache = if self.from_cache {
            " (cache local)"
        } else {
            ""
        };
        format!(
            "{cve} · CVSS {score} ({severity}) · consultada em {queried}{cache}",
            cve = self.cve_id,
            queried = self.queried_at,
        )
    }

    /// Aplica a sanitização de texto aos campos textuais.
    pub fn sanitized(&self) -> Self {
        let sanitize = crate::utils::redaction::sanitize_text;
        Self {
            cve_id: self.cve_id.to_ascii_uppercase(),
            cvss_base_score: self.cvss_base_score,
            cvss_vector: self
                .cvss_vector
                .as_deref()
                .map(|vector| sanitize(vector).replace(['\n', '\r'], " ")),
            cvss_severity: self.cvss_severity,
            cvss_version: self.cvss_version.clone(),
            reference: self
                .reference
                .as_deref()
                .map(crate::utils::redaction::sanitize_url),
            queried_at: self.queried_at.clone(),
            from_cache: self.from_cache,
        }
    }
}

/// Divergência de severidade registrada, preservando as duas classificações.
///
/// O grupo nunca escolhe um "vencedor": a severidade do scanner segue
/// autoritativa e a classificação da NVD é mantida ao lado para auditoria.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityConflict {
    /// Detalhe em pt-BR com a severidade de cada origem quereportou.
    pub detail: String,
    /// Severidade da NVD, quando o enriquecimento foi consultado.
    pub nvd_severity: Option<Severity>,
}

impl SeverityConflict {
    pub fn sanitized(&self) -> Self {
        Self {
            detail: crate::utils::redaction::sanitize_text(&self.detail),
            nvd_severity: self.nvd_severity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumo_em_pt_br_traz_cve_score_data_e_marca_cache() {
        let enrichment = CveEnrichment {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()),
            queried_at: "2026-09-30T19:11:45Z".to_string(),
            from_cache: true,
        };

        let summary = enrichment.summary_pt_br();

        assert!(summary.contains("CVE-2021-44228"), "{summary}");
        assert!(summary.contains("CVSS 10.0 (CRÍTICA)"), "{summary}");
        assert!(summary.contains("2026-09-30T19:11:45Z"), "{summary}");
        assert!(summary.contains("cache local"), "{summary}");
    }

    #[test]
    fn resumo_sem_score_nao_inventa_pontuacao() {
        let enrichment = CveEnrichment {
            cve_id: "CVE-1999-0001".to_string(),
            cvss_base_score: None,
            cvss_vector: None,
            cvss_severity: None,
            cvss_version: None,
            reference: None,
            queried_at: "2026-09-30T19:11:45Z".to_string(),
            from_cache: false,
        };

        let summary = enrichment.summary_pt_br();

        assert!(summary.contains("não pontuado"), "{summary}");
        assert!(summary.contains("NÃO INFORMADA"), "{summary}");
        assert!(!summary.contains("cache local"), "{summary}");
    }

    #[test]
    fn sanitizacao_remove_credencial_da_referencia_e_quebra_o_vetor() {
        let enrichment = CveEnrichment {
            cve_id: "cve-2021-44228".to_string(),
            cvss_base_score: Some(7.5),
            cvss_vector: Some("CVSS:3.1/AV:N\nAuthorization: Bearer secret".to_string()),
            cvss_severity: Some(Severity::High),
            cvss_version: Some("3.1".to_string()),
            reference: Some(
                "https://user:secret@nvd.nist.gov/vuln/detail/CVE-2021-44228?token=secret"
                    .to_string(),
            ),
            queried_at: "2026-09-30T19:11:45Z".to_string(),
            from_cache: false,
        };

        let sanitized = enrichment.sanitized();

        assert_eq!(sanitized.cve_id, "CVE-2021-44228");
        assert_eq!(
            sanitized.reference.as_deref(),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
        );
        assert!(!sanitized.cvss_vector.as_deref().unwrap().contains('\n'));
        let serialized = serde_json::to_string(&sanitized).expect("serialização falha");
        assert!(!serialized.contains("secret"), "{serialized}");
    }
}
