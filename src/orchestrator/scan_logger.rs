use crate::domain::vulnerability::Vulnerability;
use crate::domain::Severity;
use crate::orchestrator::decision::DecisionRecord;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Registro estruturado de execução de uma ferramenta de segurança.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolExecutionRecord {
    pub tool_name: String,
    pub arguments: Vec<String>,
    pub executed_at: String,
    pub output_bytes: usize,
    pub output_sample: String,
    pub stdout: String,
    pub stderr: String,
    pub status: String,
    pub duration_ms: u128,
    pub tool_version: Option<String>,
    pub image: Option<String>,
    #[serde(default)]
    pub execution_error: Option<String>,
    /// Trace operacional completo do Podman (comandos, pull, start, limpeza).
    #[serde(default)]
    pub podman_trace: Vec<String>,
}

impl ToolExecutionRecord {
    fn sanitized(&self) -> Self {
        let sanitize = crate::utils::redaction::sanitize_text;
        Self {
            tool_name: sanitize(&self.tool_name),
            arguments: self.arguments.iter().map(|value| sanitize(value)).collect(),
            executed_at: sanitize(&self.executed_at),
            output_bytes: self.output_bytes,
            output_sample: sanitize(&self.output_sample),
            stdout: sanitize(&self.stdout),
            stderr: sanitize(&self.stderr),
            status: sanitize(&self.status),
            duration_ms: self.duration_ms,
            tool_version: self.tool_version.as_deref().map(sanitize),
            image: self.image.as_deref().map(sanitize),
            execution_error: self.execution_error.as_deref().map(sanitize),
            podman_trace: self
                .podman_trace
                .iter()
                .map(|line| sanitize(line))
                .collect(),
        }
    }
}

/// Metadados e log estruturado completo de um scan de segurança.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScanMetadata {
    pub scan_id: String,
    pub target_url: String,
    pub started_at: String,
    pub completed_at: String,
    pub execution_type: String,
    /// Provedor de IA **configurado**, em pt-BR (ex.: `OpenAI`).
    pub llm_provider: String,
    /// Modelo que produziu as orientações; vazio quando a análise foi
    /// determinística (nenhuma IA respondeu dentro do contrato).
    #[serde(default)]
    pub llm_model: String,
    /// Provedor que **efetivamente** respondeu, em pt-BR. Difere de
    /// `llm_provider` quando a alternativa local respondem, e vale `Nenhuma`
    /// quando a análise foi determinística.
    #[serde(default)]
    pub llm_provider_effective: String,
    /// `true` quando o provedor principal falhou e a alternativa respondeu.
    #[serde(default)]
    pub llm_fallback_used: bool,
    /// Motivo pelo qual as orientações da IA não foram aceitas, quando for o
    /// caso (timeout, consentimento ausente, resposta fora do contrato).
    #[serde(default)]
    pub llm_failure_reason: Option<String>,
    /// Horário da análise por IA em ISO-8601 (UTC).
    #[serde(default)]
    pub llm_analyzed_at: String,
    /// Quantos trechos do scanner foram neutralizados por tentativa de injeção
    /// de prompt antes de serem enviados ao modelo.
    #[serde(default)]
    pub llm_neutralized_snippets: usize,
    pub tools_executed: Vec<ToolExecutionRecord>,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    #[serde(default)]
    pub info_count: usize,
    pub findings: Vec<serde_json::Value>,
    pub agent_analysis: String,
    #[serde(default)]
    pub decisions: Vec<DecisionRecord>,
}

/// Resumo compacto para listagem de scans históricos.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ScanRecordSummary {
    pub scan_id: String,
    pub target_url: String,
    pub completed_at: String,
    pub findings_count: usize,
    pub file_path: PathBuf,
}

impl ScanMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scan_id: String,
        target_url: String,
        started_at: String,
        completed_at: String,
        execution_type: String,
        llm_provider: String,
        tools_executed: Vec<ToolExecutionRecord>,
        findings: Vec<Vulnerability>,
        agent_analysis: String,
    ) -> Self {
        let findings_count = findings.len();
        let critical_count = findings
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .count();
        let info_count = findings
            .iter()
            .filter(|v| v.severity == Severity::Info)
            .count();

        Self {
            scan_id,
            target_url: crate::utils::redaction::sanitize_url(&target_url),
            started_at,
            completed_at,
            execution_type,
            llm_provider: crate::utils::redaction::sanitize_text(&llm_provider),
            llm_model: String::new(),
            llm_provider_effective: String::new(),
            llm_fallback_used: false,
            llm_failure_reason: None,
            llm_analyzed_at: String::new(),
            llm_neutralized_snippets: 0,
            tools_executed: tools_executed
                .iter()
                .map(ToolExecutionRecord::sanitized)
                .collect(),
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            findings: findings
                .iter()
                .map(Vulnerability::sanitized)
                .map(|finding| serde_json::to_value(finding).unwrap_or(serde_json::Value::Null))
                .collect(),
            agent_analysis: crate::utils::redaction::sanitize_text(&agent_analysis),
            decisions: Vec::new(),
        }
    }

    /// Anexa a proveniência da análise da IA ao log estruturado.
    ///
    /// Sem esta chamada os campos novos ficam vazios: um scan cancelado antes
    /// da análise é persistido assim, deixando explícito que a IA não respondeu.
    pub fn with_analysis(mut self, result: &crate::ai::analysis_service::AnalysisResult) -> Self {
        self.llm_model = crate::utils::redaction::sanitize_text(&result.model);
        self.llm_provider_effective = crate::utils::redaction::sanitize_text(&result.provider);
        self.llm_fallback_used = result.fallback_used;
        // O motivo da falha é um diagnóstico do próprio SmartSec: usa a
        // sanitização de diagnóstico, que preserva a frase e remove apenas a
        // credencial. A sanitização de texto de scanner a substituiria por
        // `[REDACTED]`, já que o erro de transporte menciona "request".
        self.llm_failure_reason = result
            .failure_reason
            .as_deref()
            .map(crate::utils::redaction::sanitize_diagnostic);
        self.llm_analyzed_at = crate::utils::redaction::sanitize_text(&result.analyzed_at);
        self.llm_neutralized_snippets = result.neutralized_snippets;
        self
    }

    fn sanitized(&self) -> Self {
        let sanitize = crate::utils::redaction::sanitize_text;
        let mut findings = self.findings.clone();
        for finding in &mut findings {
            crate::utils::redaction::sanitize_json_value(finding);
        }
        Self {
            scan_id: sanitize(&self.scan_id),
            target_url: crate::utils::redaction::sanitize_url(&self.target_url),
            started_at: sanitize(&self.started_at),
            completed_at: sanitize(&self.completed_at),
            execution_type: sanitize(&self.execution_type),
            llm_provider: sanitize(&self.llm_provider),
            llm_model: sanitize(&self.llm_model),
            llm_provider_effective: sanitize(&self.llm_provider_effective),
            llm_fallback_used: self.llm_fallback_used,
            llm_failure_reason: self
                .llm_failure_reason
                .as_deref()
                .map(crate::utils::redaction::sanitize_diagnostic),
            llm_analyzed_at: sanitize(&self.llm_analyzed_at),
            llm_neutralized_snippets: self.llm_neutralized_snippets,
            tools_executed: self
                .tools_executed
                .iter()
                .map(ToolExecutionRecord::sanitized)
                .collect(),
            findings_count: self.findings_count,
            critical_count: self.critical_count,
            high_count: self.high_count,
            medium_count: self.medium_count,
            low_count: self.low_count,
            info_count: self.info_count,
            findings,
            agent_analysis: sanitize(&self.agent_analysis),
            decisions: self
                .decisions
                .iter()
                .map(DecisionRecord::sanitized)
                .collect(),
        }
    }
}

/// Retorna o diretório base para armazenamento de logs de scans.
pub fn scans_dir() -> PathBuf {
    let base = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smartsec")
        .join("scans");
    let _ = fs::create_dir_all(&base);
    base
}

/// Salva os metadados de um scan em arquivo JSON estruturado.
pub fn save_scan_log(metadata: &ScanMetadata) -> Result<PathBuf> {
    let dir = scans_dir();
    save_scan_log_to_dir(metadata, &dir)
}

/// Salva os metadados em um diretório específico (útil para testes).
pub fn save_scan_log_to_dir(metadata: &ScanMetadata, target_dir: &PathBuf) -> Result<PathBuf> {
    fs::create_dir_all(target_dir).context("Falha ao criar diretório de scans")?;
    let metadata = metadata.sanitized();
    let filename = format!("{}.json", metadata.scan_id);
    let path = target_dir.join(filename);

    let json_data = serde_json::to_string_pretty(&metadata)
        .context("Falha ao serializar metadados do scan para JSON")?;

    fs::write(&path, json_data)
        .with_context(|| format!("Falha ao gravar arquivo de scan em {:?}", path))?;

    Ok(path)
}

/// Lista o resumo de todos os scans estruturados gravados em um diretório.
#[allow(dead_code)]
pub fn list_scan_logs_from_dir(dir: &PathBuf) -> Result<Vec<ScanRecordSummary>> {
    let mut summaries = Vec::new();
    if !dir.exists() {
        return Ok(summaries);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<ScanMetadata>(&content) {
                    summaries.push(ScanRecordSummary {
                        scan_id: meta.scan_id,
                        target_url: meta.target_url,
                        completed_at: meta.completed_at,
                        findings_count: meta.findings_count,
                        file_path: path,
                    });
                }
            }
        }
    }

    summaries.sort_by(|a, b| b.completed_at.cmp(&a.completed_at));
    Ok(summaries)
}

/// Carrega os metadados completos de um scan dado seu caminho de arquivo.
#[allow(dead_code)]
pub fn load_scan_log_from_file(file_path: &PathBuf) -> Result<ScanMetadata> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Falha ao ler arquivo de log {:?}", file_path))?;
    let meta: ScanMetadata = serde_json::from_str(&content)
        .with_context(|| format!("Falha ao deserializar JSON de {:?}", file_path))?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    #[test]
    fn test_save_and_load_scan_log() {
        let temp_dir =
            std::env::temp_dir().join(format!("smartsec_test_scans_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);

        let metadata = ScanMetadata::new(
            "scan_20260831_120000".to_string(),
            "http://target.local".to_string(),
            "2026-08-31T12:00:00Z".to_string(),
            "2026-08-31T12:05:00Z".to_string(),
            "Auto".to_string(),
            "Mock".to_string(),
            vec![ToolExecutionRecord {
                tool_name: "Nuclei".to_string(),
                arguments: vec!["-u".to_string(), "http://target.local".to_string()],
                executed_at: "2026-08-31T12:01:00Z".to_string(),
                output_bytes: 120,
                output_sample: "found test vuln".to_string(),
                stdout: "found test vuln".to_string(),
                stderr: String::new(),
                status: "succeeded".to_string(),
                duration_ms: 10,
                tool_version: Some("test".to_string()),
                image: None,
                execution_error: None,
                podman_trace: vec!["[12:01:00] $ podman create --name smartsec-test".to_string()],
            }],
            vec![
                Vulnerability {
                    title: "Test Vuln".to_string(),
                    severity: Severity::High,
                    description: "Test description".to_string(),
                    tool: "Nuclei".to_string(),
                    recommendation: "Fix it".to_string(),
                    didactic: "Didactic text".to_string(),
                    source: FindingSource::Real,
                    target: "http://target.local".to_string(),
                    evidence: "test evidence".to_string(),
                    detected_at: "2026-08-31T12:01:00Z".to_string(),
                },
                Vulnerability {
                    title: "Informational finding".to_string(),
                    severity: Severity::Info,
                    description: "Informational description".to_string(),
                    tool: "Nmap".to_string(),
                    recommendation: "Review it".to_string(),
                    didactic: "Didactic text".to_string(),
                    source: FindingSource::Real,
                    target: "http://target.local".to_string(),
                    evidence: "port open".to_string(),
                    detected_at: "2026-08-31T12:01:00Z".to_string(),
                },
            ],
            "AI Analysis text".to_string(),
        );

        let mut legacy_json = serde_json::to_value(&metadata).unwrap();
        legacy_json.as_object_mut().unwrap().remove("info_count");
        legacy_json["tools_executed"][0]
            .as_object_mut()
            .unwrap()
            .remove("podman_trace");
        let legacy: ScanMetadata = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(legacy.info_count, 0);
        assert!(legacy.tools_executed[0].podman_trace.is_empty());

        let path = save_scan_log_to_dir(&metadata, &temp_dir).expect("save should succeed");
        assert!(path.exists());

        let loaded = load_scan_log_from_file(&path).expect("load should succeed");
        assert_eq!(
            loaded.tools_executed[0].podman_trace,
            vec!["[12:01:00] $ podman create --name smartsec-test".to_string()]
        );
        assert_eq!(loaded.scan_id, "scan_20260831_120000");
        assert_eq!(loaded.findings_count, 2);
        assert_eq!(loaded.high_count, 1);
        assert_eq!(loaded.critical_count, 0);
        assert_eq!(loaded.info_count, 1);

        let summaries = list_scan_logs_from_dir(&temp_dir).expect("list should succeed");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].scan_id, "scan_20260831_120000");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn persisted_scan_keeps_the_model_provider_fallback_and_time_of_the_analysis() {
        use crate::ai::analysis_service::{AnalysisResult, AnalysisSource};

        let temp_dir =
            std::env::temp_dir().join(format!("smartsec_test_proveniencia_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);

        let metadata = ScanMetadata::new(
            "scan-proveniencia".to_string(),
            "http://target.local".to_string(),
            "2026-09-30T12:00:00Z".to_string(),
            "2026-09-30T12:05:00Z".to_string(),
            "Automatico".to_string(),
            "OpenAI".to_string(),
            vec![],
            vec![],
            "Análise concluída: 1 achados".to_string(),
        )
        .with_analysis(&AnalysisResult {
            text: "Análise concluída: 1 achados".to_string(),
            model: "llama3.1:8b".to_string(),
            provider: "Ollama".to_string(),
            configured_provider: "OpenAI".to_string(),
            source: AnalysisSource::FallbackProvider,
            fallback_used: true,
            failure_reason: Some("a LLM principal falhou".to_string()),
            analyzed_at: "2026-09-30T12:04:59Z".to_string(),
            neutralized_snippets: 2,
        });

        let path = save_scan_log_to_dir(&metadata, &temp_dir).expect("save should succeed");
        let loaded = load_scan_log_from_file(&path).expect("load should succeed");

        assert_eq!(loaded.llm_provider, "OpenAI");
        assert_eq!(loaded.llm_model, "llama3.1:8b");
        assert_eq!(loaded.llm_provider_effective, "Ollama");
        assert!(loaded.llm_fallback_used);
        assert_eq!(
            loaded.llm_failure_reason.as_deref(),
            Some("a LLM principal falhou")
        );
        assert_eq!(loaded.llm_analyzed_at, "2026-09-30T12:04:59Z");
        assert_eq!(loaded.llm_neutralized_snippets, 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    /// O `serde(default)` precisa estar em **todos** os campos novos, e não só
    /// em alguns. Este teste serializa um metadado completo e remove os campos
    /// de proveniência um a um: basta um deles sem `#[serde(default)]` para a
    /// desserialização de um histórico antigo falhar, e a falha só apareceria em
    /// produção, ao abrir um scan gravado antes desta issue.
    /// O motivo da falha precisa sobreviver à redação.
    ///
    /// Regressão: a sanitização de texto de scanner substitui a linha inteira
    /// por `[REDACTED]` quando encontra `request`, e o erro de transporte do
    /// cliente HTTP sempre menciona "request". O campo `llm_failure_reason`
    /// virava `[REDACTED]` em toda queda de provedor, ou seja, o registro
    /// dizia que houve fallback sem dizer por quê.
    #[test]
    fn failure_reason_survives_redaction_with_the_reason_intact() {
        let metadata = ScanMetadata::new(
            "scan-motivo".to_string(),
            "http://target.local".to_string(),
            "2026-09-30T12:00:00Z".to_string(),
            "2026-09-30T12:05:00Z".to_string(),
            "Automatico".to_string(),
            "OpenAI".to_string(),
            vec![],
            vec![],
            "Análise concluída".to_string(),
        )
        .with_analysis(&crate::ai::analysis_service::AnalysisResult {
            text: "Análise concluída".to_string(),
            model: "llama3.1:8b".to_string(),
            provider: "Ollama".to_string(),
            configured_provider: "OpenAI".to_string(),
            source: crate::ai::analysis_service::AnalysisSource::FallbackProvider,
            fallback_used: true,
            failure_reason: Some(
                "error sending request for url (http://127.0.0.1:8080/v1/chat/completions)"
                    .to_string(),
            ),
            analyzed_at: "2026-09-30T12:04:59Z".to_string(),
            neutralized_snippets: 0,
        });

        let reason = metadata
            .llm_failure_reason
            .as_deref()
            .expect("o motivo da falha precisa ser preservado");
        assert!(
            reason.contains("error sending request"),
            "o motivo foi destruído pela redação: {reason}"
        );
        assert_ne!(reason, "[REDACTED]");
    }

    /// A credencial continua removida do motivo da falha: a preservação da
    /// frase não pode virar um caminho para gravar segredo no log.
    #[test]
    fn failure_reason_still_drops_credentials() {
        let metadata = ScanMetadata::new(
            "scan-credencial".to_string(),
            "http://target.local".to_string(),
            "2026-09-30T12:00:00Z".to_string(),
            "2026-09-30T12:05:00Z".to_string(),
            "Automatico".to_string(),
            "OpenAI".to_string(),
            vec![],
            vec![],
            "Análise concluída".to_string(),
        )
        .with_analysis(&crate::ai::analysis_service::AnalysisResult {
            text: "Análise concluída".to_string(),
            model: "gpt-4o".to_string(),
            provider: "OpenAI".to_string(),
            configured_provider: "OpenAI".to_string(),
            source: crate::ai::analysis_service::AnalysisSource::Deterministic,
            fallback_used: false,
            failure_reason: Some("401 Unauthorized: api_key=sk-secreto-real".to_string()),
            analyzed_at: "2026-09-30T12:04:59Z".to_string(),
            neutralized_snippets: 0,
        });

        let reason = metadata.llm_failure_reason.as_deref().unwrap();
        assert!(!reason.contains("sk-secreto-real"), "{reason}");
    }

    #[test]
    fn every_new_provenance_field_deserializes_when_absent() {
        let full = ScanMetadata::new(
            "scan-campos".to_string(),
            "http://target.local".to_string(),
            "2026-09-30T12:00:00Z".to_string(),
            "2026-09-30T12:05:00Z".to_string(),
            "Automatico".to_string(),
            "OpenAI".to_string(),
            vec![],
            vec![],
            "Análise concluída".to_string(),
        )
        .with_analysis(&crate::ai::analysis_service::AnalysisResult {
            text: "Análise concluída".to_string(),
            model: "gpt-4o".to_string(),
            provider: "OpenAI".to_string(),
            configured_provider: "OpenAI".to_string(),
            source: crate::ai::analysis_service::AnalysisSource::PrimaryProvider,
            fallback_used: false,
            failure_reason: None,
            analyzed_at: "2026-09-30T12:04:59Z".to_string(),
            neutralized_snippets: 0,
        });

        for field in [
            "llm_model",
            "llm_provider_effective",
            "llm_fallback_used",
            "llm_failure_reason",
            "llm_analyzed_at",
            "llm_neutralized_snippets",
        ] {
            let mut legacy = serde_json::to_value(&full).unwrap();
            legacy
                .as_object_mut()
                .expect("metadado serializado")
                .remove(field);

            let restored: ScanMetadata = serde_json::from_value(legacy)
                .unwrap_or_else(|error| panic!("sem `serde(default)`, {field} quebra: {error}"));
            assert_eq!(restored.llm_provider, "OpenAI", "{field}");
        }
    }

    #[test]
    fn scan_metadata_from_an_earlier_version_without_llm_provenance_still_loads() {
        let metadata = ScanMetadata::new(
            "scan-legado".to_string(),
            "http://target.local".to_string(),
            "2026-08-31T12:00:00Z".to_string(),
            "2026-08-31T12:05:00Z".to_string(),
            "Assistido".to_string(),
            "Ollama".to_string(),
            vec![],
            vec![],
            "Análise concluída".to_string(),
        );

        let mut legacy = serde_json::to_value(&metadata).unwrap();
        let object = legacy.as_object_mut().unwrap();
        for field in [
            "llm_model",
            "llm_provider_effective",
            "llm_fallback_used",
            "llm_failure_reason",
            "llm_analyzed_at",
            "llm_neutralized_snippets",
        ] {
            object.remove(field);
        }

        let restored: ScanMetadata = serde_json::from_value(legacy).expect("histórico antigo");

        assert_eq!(restored.llm_model, "");
        assert_eq!(restored.llm_provider_effective, "");
        assert!(!restored.llm_fallback_used);
        assert!(restored.llm_failure_reason.is_none());
        assert_eq!(restored.llm_analyzed_at, "");
        assert_eq!(restored.llm_neutralized_snippets, 0);
        assert_eq!(restored.llm_provider, "Ollama");
    }

    #[test]
    fn persisted_scan_removes_http_payloads_and_credentials() {
        let metadata = ScanMetadata::new(
            "scan-seguro".to_string(),
            "https://user:secret@target.local/path?token=secret".to_string(),
            "2026-09-06T12:00:00Z".to_string(),
            "2026-09-06T12:01:00Z".to_string(),
            "Auto".to_string(),
            "Ollama".to_string(),
            vec![ToolExecutionRecord {
                tool_name: "Nuclei".to_string(),
                arguments: vec![
                    "-u".to_string(),
                    "https://target.local/path?token=secret".to_string(),
                ],
                executed_at: "2026-09-06T12:00:01Z".to_string(),
                output_bytes: 100,
                output_sample: "request: Authorization: Bearer secret".to_string(),
                stdout: r#"{"template-id":"headers","request":"secret","response":"secret","url":"https://target.local/path?token=secret"}"#.to_string(),
                stderr: "Authorization: Bearer secret".to_string(),
                status: "succeeded".to_string(),
                duration_ms: 1,
                tool_version: None,
                image: None,
                execution_error: None,
                podman_trace: vec![
                    "podman run https://target.local/path?token=secret".to_string(),
                ],
            }],
            vec![Vulnerability {
                title: "Cabeçalhos".to_string(),
                severity: Severity::Info,
                description: "Descrição segura".to_string(),
                tool: "Nuclei".to_string(),
                recommendation: "Revise".to_string(),
                didactic: "Explicação".to_string(),
                source: FindingSource::Real,
                target: "https://target.local/path?token=secret".to_string(),
                evidence: "request: secret".to_string(),
                detected_at: "2026-09-06T12:00:01Z".to_string(),
            }],
            "Authorization: Bearer secret".to_string(),
        );

        let serialized = serde_json::to_string(&metadata).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("?token="));
        assert!(!serialized.contains("\"request\""));
        assert!(!serialized.contains("\"response\""));
        assert!(serialized.contains("template-id"));
        assert!(serialized.contains("[REDACTED]"));
    }
}
