use crate::domain::vulnerability::Vulnerability;
use crate::domain::Severity;
use crate::orchestrator::decision::DecisionRecord;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Concordância de número para os textos de interface em pt-BR.
fn plural(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

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
    pub llm_provider: String,
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
    /// Resumo da correlação e do enriquecimento CVE/NVD (issue #19).
    ///
    /// `#[serde(default)]` porque logs gravados antes da issue #19 não têm
    /// esta chave e precisam continuar carregando.
    #[serde(default)]
    pub enrichment: crate::orchestrator::enrichment::EnrichmentSummary,
}

/// Contagem de achados por severidade usada na listagem do histórico.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSeverityCounts {
    pub fn from_metadata(meta: &ScanMetadata) -> Self {
        Self {
            critical: meta.critical_count,
            high: meta.high_count,
            medium: meta.medium_count,
            low: meta.low_count,
            info: meta.info_count,
        }
    }

    /// Total de achados contabilizados por severidade.
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Resumo em uma linha para a listagem do histórico, em pt-BR.
    pub fn label(&self) -> String {
        format!(
            "{} · {} · {} · {} · {} · {}",
            plural(self.total(), "achado", "achados"),
            plural(self.critical, "crítica", "críticas"),
            plural(self.high, "alta", "altas"),
            plural(self.medium, "média", "médias"),
            plural(self.low, "baixa", "baixas"),
            plural(self.info, "informativa", "informativas"),
        )
    }
}

/// Resumo compacto para listagem de scans históricos.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecordSummary {
    pub scan_id: String,
    pub target_url: String,
    pub started_at: String,
    pub completed_at: String,
    pub execution_type: String,
    pub findings_count: usize,
    pub severity_counts: ScanSeverityCounts,
    pub file_path: PathBuf,
}

/// Registro presente no diretório de histórico que não pôde ser consultado.
///
/// Um registro ilegível nunca desaparece em silêncio: ele volta para o usuário
/// como item identificável da listagem.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnreadableScanRecord {
    pub file_name: String,
    pub reason: String,
}

/// Resultado de uma consulta ao histórico: o que foi lido e o que ficou ilegível.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanHistory {
    /// `false` quando o diretório de execuções ainda não existe.
    pub directory_exists: bool,
    pub records: Vec<ScanRecordSummary>,
    pub unreadable: Vec<UnreadableScanRecord>,
}

impl ScanHistory {
    /// `true` quando o diretório existe mas não possui registro consultável.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.unreadable.is_empty()
    }

    /// Aviso em pt-BR sobre registros ilegíveis, ou `None` quando tudo leu.
    pub fn unreadable_warning(&self) -> Option<String> {
        if self.unreadable.is_empty() {
            return None;
        }
        if self.unreadable.len() == 1 {
            Some("1 registro ilegível foi ignorado na listagem:".to_string())
        } else {
            Some(format!(
                "{} registros ilegíveis foram ignorados na listagem:",
                self.unreadable.len()
            ))
        }
    }
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
            enrichment: crate::orchestrator::enrichment::EnrichmentSummary::default(),
        }
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
            enrichment: crate::orchestrator::enrichment::EnrichmentSummary {
                correlation: self.enrichment.correlation.clone(),
                nvd: crate::orchestrator::nvd::NvdReport {
                    consulted: self.enrichment.nvd.consulted,
                    enriched: self.enrichment.nvd.enriched,
                    cached: self.enrichment.nvd.cached,
                    not_found: self.enrichment.nvd.not_found,
                    unavailable_reasons: self
                        .enrichment
                        .nvd
                        .unavailable_reasons
                        .iter()
                        .map(|reason| crate::utils::redaction::sanitize_text(reason))
                        .collect(),
                },
            },
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
///
/// A listagem é somente leitura: nenhum arquivo do diretório é criado,
/// reescrito ou removido. Registros ilegíveis são devolvidos em
/// [`ScanHistory::unreadable`] em vez de sumirem em silêncio.
pub fn list_scan_logs_from_dir(dir: &PathBuf) -> Result<ScanHistory> {
    let mut history = ScanHistory {
        directory_exists: dir.exists(),
        ..ScanHistory::default()
    };
    if !dir.exists() {
        return Ok(history);
    }

    let entries = fs::read_dir(dir)
        .with_context(|| format!("Falha ao ler o diretório de histórico {dir:?}"))?;
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => {
                history.unreadable.push(UnreadableScanRecord {
                    file_name: "<entrada ilegível>".to_string(),
                    reason: format!("não foi possível ler a entrada do diretório: {error}"),
                });
                continue;
            }
        };
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<ScanMetadata>(&content) {
                Ok(meta) => history.records.push(ScanRecordSummary {
                    scan_id: meta.scan_id.clone(),
                    target_url: meta.target_url.clone(),
                    started_at: meta.started_at.clone(),
                    completed_at: meta.completed_at.clone(),
                    execution_type: meta.execution_type.clone(),
                    findings_count: meta.findings_count,
                    severity_counts: ScanSeverityCounts::from_metadata(&meta),
                    file_path: path,
                }),
                Err(error) => history.unreadable.push(UnreadableScanRecord {
                    file_name,
                    reason: format!("conteúdo inválido ou incompleto: {error}"),
                }),
            },
            Err(error) => history.unreadable.push(UnreadableScanRecord {
                file_name,
                reason: format!("não foi possível ler o arquivo: {error}"),
            }),
        }
    }

    history
        .records
        .sort_by(|a, b| b.completed_at.cmp(&a.completed_at));
    Ok(history)
}

/// Indica se o identificador segue o padrão `scan_<nanos>` gerado pelo orquestrador.
///
/// O padrão é ASCII e não contém separadores de caminho, portanto um id fora do
/// padrão nunca pode ser convertido em um caminho arbitrário.
pub fn is_valid_scan_id(scan_id: &str) -> bool {
    let Some(digits) = scan_id.strip_prefix("scan_") else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Resolve o caminho do registro de um `scan_id` dentro de [`scans_dir`].
///
/// Rejeita path traversal e qualquer id fora do padrão `scan_<nanos>`; o id nunca
/// pode apontar para fora do diretório de histórico.
pub fn scan_log_path(scan_id: &str) -> Result<PathBuf> {
    if !is_valid_scan_id(scan_id) {
        anyhow::bail!(
            "identificador de execução inválido: {scan_id}; esperado no formato scan_<nanos>"
        );
    }
    let dir = scans_dir();
    let path = dir.join(format!("{scan_id}.json"));
    debug_assert_eq!(path.parent(), Some(dir.as_path()));
    Ok(path)
}

/// Carrega os metadados completos de um scan dado seu caminho de arquivo.
pub fn load_scan_log_from_file(file_path: &PathBuf) -> Result<ScanMetadata> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Falha ao ler o registro de execução em {file_path:?}"))?;
    let meta: ScanMetadata = serde_json::from_str(&content).with_context(|| {
        format!(
            "Falha ao interpretar o registro de execução em {file_path:?}; \
             o arquivo pode estar corrompido, incompleto ou em uma versão anterior do formato"
        )
    })?;
    Ok(meta)
}

/// Carrega uma execução do histórico pelo `scan_id` informado pelo usuário.
pub fn load_scan_log_by_id(scan_id: &str) -> Result<ScanMetadata> {
    let path = scan_log_path(scan_id)?;
    if !path.is_file() {
        anyhow::bail!("execução não encontrada no histórico: {scan_id}");
    }
    load_scan_log_from_file(&path)
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
                    origins: Vec::new(),
                    enrichment: None,
                    severity_conflict: None,
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
                    origins: Vec::new(),
                    enrichment: None,
                    severity_conflict: None,
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

        let history = list_scan_logs_from_dir(&temp_dir).expect("list should succeed");
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].scan_id, "scan_20260831_120000");

        let _ = fs::remove_dir_all(&temp_dir);
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
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
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

    // ---------- Histórico consultável (issue #24) ----------

    /// Diretório exclusivo por teste: evita colisão entre threads do mesmo binário.
    fn history_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "smartsec_historico_{label}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn sample_metadata(scan_id: &str, completed_at: &str, target: &str) -> ScanMetadata {
        ScanMetadata {
            scan_id: scan_id.to_string(),
            target_url: target.to_string(),
            started_at: "2026-09-01T10:00:00Z".to_string(),
            completed_at: completed_at.to_string(),
            execution_type: "Auto".to_string(),
            llm_provider: "Ollama".to_string(),
            tools_executed: Vec::new(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            findings: Vec::new(),
            agent_analysis: "Analise local".to_string(),
            decisions: Vec::new(),
            enrichment: Default::default(),
        }
    }

    /// Fotografia byte a byte do diretório para provar que a consulta é somente leitura.
    fn snapshot_bytes(dir: &PathBuf) -> Vec<(String, Vec<u8>)> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .expect("o diretório de histórico deve ser legível")
            .map(|entry| {
                let path = entry.expect("entrada legível").path();
                let name = path
                    .file_name()
                    .expect("entrada com nome")
                    .to_string_lossy()
                    .into_owned();
                (name, fs::read(&path).expect("conteúdo legível"))
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    #[test]
    fn empty_and_missing_history_are_distinguishable() {
        let missing = history_dir("inexistente");
        let _ = fs::remove_dir_all(&missing);

        let history = list_scan_logs_from_dir(&missing).expect("listar não pode falhar");

        assert!(
            !history.directory_exists,
            "diretório inexistente precisa ser distinguido de vazio"
        );
        assert!(history.is_empty());
        assert!(history.unreadable_warning().is_none());

        let empty = history_dir("vazio");
        let _ = fs::remove_dir_all(&empty);
        fs::create_dir_all(&empty).unwrap();

        let history = list_scan_logs_from_dir(&empty).expect("listar não pode falhar");

        assert!(history.directory_exists, "diretório vazio existe");
        assert!(
            history.is_empty(),
            "diretório vazio não tem registros nem ilegíveis"
        );

        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn complete_history_is_ordered_by_completion_without_touching_the_files() {
        let dir = history_dir("completo");
        let _ = fs::remove_dir_all(&dir);

        for (scan_id, completed_at, target) in [
            (
                "scan_1000000000000000001",
                "2026-09-01T10:00:00Z",
                "http://antigo.local",
            ),
            (
                "scan_1000000000000000003",
                "2026-09-03T10:00:00Z",
                "http://recente.local",
            ),
            (
                "scan_1000000000000000002",
                "2026-09-02T10:00:00Z",
                "http://medio.local",
            ),
        ] {
            let mut metadata = sample_metadata(scan_id, completed_at, target);
            metadata.critical_count = 1;
            metadata.info_count = 2;
            metadata.findings_count = 3;
            save_scan_log_to_dir(&metadata, &dir).expect("gravação de teste");
        }
        let before = snapshot_bytes(&dir);

        let history = list_scan_logs_from_dir(&dir).expect("listagem deve funcionar");

        assert_eq!(
            history
                .records
                .iter()
                .map(|record| record.scan_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "scan_1000000000000000003",
                "scan_1000000000000000002",
                "scan_1000000000000000001"
            ],
            "a listagem ordena da mais recente para a mais antiga"
        );
        assert!(
            history.records[0]
                .target_url
                .starts_with("http://recente.local"),
            "alvo sanitizado: {}",
            history.records[0].target_url
        );
        assert_eq!(history.records[0].severity_counts.total(), 3);
        assert_eq!(history.records[0].severity_counts.critical, 1);
        assert!(history.unreadable.is_empty());
        assert!(history.unreadable_warning().is_none());

        for record in &history.records {
            load_scan_log_from_file(&record.file_path).expect("abertura deve funcionar");
        }
        assert_eq!(
            snapshot_bytes(&dir),
            before,
            "a consulta ao historico nao pode alterar os artefatos originais (criterio d)"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_record_is_reported_instead_of_disappearing() {
        let dir = history_dir("corrompido");
        let _ = fs::remove_dir_all(&dir);

        let valid = sample_metadata(
            "scan_1000000000000000010",
            "2026-09-01T10:00:00Z",
            "http://valido.local",
        );
        save_scan_log_to_dir(&valid, &dir).expect("gravação de teste");
        fs::write(
            dir.join("scan_1000000000000000011.json"),
            "{isto nao e json",
        )
        .expect("gravação do registro corrompido");
        let before = snapshot_bytes(&dir);

        let history = list_scan_logs_from_dir(&dir).expect("listagem deve funcionar");

        assert_eq!(
            history.records.len(),
            1,
            "o registro válido continua legível"
        );
        assert_eq!(history.unreadable.len(), 1);
        assert_eq!(
            history.unreadable[0].file_name,
            "scan_1000000000000000011.json"
        );
        assert!(
            history.unreadable[0].reason.contains("conteúdo inválido"),
            "o motivo deve ser acionável: {}",
            history.unreadable[0].reason
        );
        let warning = history
            .unreadable_warning()
            .expect("registro ilegivel gera aviso");
        assert!(warning.contains('1'), "{warning}");

        assert_eq!(
            snapshot_bytes(&dir),
            before,
            "listar um diretorio corrompido nao pode reescrever o arquivo quebrado"
        );

        let error = load_scan_log_from_file(&dir.join("scan_1000000000000000011.json"))
            .expect_err("registro corrompido nao pode carregar");
        let message = format!("{error:#}");
        assert!(message.contains("Falha ao interpretar"), "{message}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_record_fails_with_an_actionable_message() {
        let dir = history_dir("parcial");
        let _ = fs::remove_dir_all(&dir);

        // Registro truncado: os campos obrigatórios de topo continuam ausentes.
        let partial = r#"{"scan_id":"scan_1000000000000000020","findings":[]}"#;
        let path = dir.join("scan_1000000000000000020.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, partial).expect("gravação do registro parcial");
        let before = snapshot_bytes(&dir);

        let history = list_scan_logs_from_dir(&dir).expect("listagem deve funcionar");
        assert!(history.records.is_empty());
        assert_eq!(history.unreadable.len(), 1);

        let error = load_scan_log_from_file(&path).expect_err("registro parcial nao carrega");
        let message = format!("{error:#}");
        assert!(message.contains("corrompido"), "{message}");
        assert!(message.contains("versão anterior"), "{message}");

        assert_eq!(
            snapshot_bytes(&dir),
            before,
            "falha de leitura nao pode alterar o registro parcial"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn previous_version_without_new_fields_is_readable() {
        let dir = history_dir("versao_anterior");
        let _ = fs::remove_dir_all(&dir);

        let mut metadata = sample_metadata(
            "scan_1000000000000000030",
            "2026-09-01T10:00:00Z",
            "http://legado.local",
        );
        metadata.tools_executed = vec![ToolExecutionRecord {
            tool_name: "Nmap".to_string(),
            arguments: vec!["-sT".to_string()],
            executed_at: "2026-09-01T10:00:30Z".to_string(),
            output_bytes: 10,
            output_sample: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            status: "succeeded".to_string(),
            duration_ms: 30,
            tool_version: Some("7.94".to_string()),
            image: Some("imagem:1".to_string()),
            execution_error: None,
            podman_trace: Vec::new(),
        }];
        let mut legacy_json = serde_json::to_value(&metadata).unwrap();
        let object = legacy_json.as_object_mut().unwrap();
        object.remove("info_count");
        object.remove("decisions");
        legacy_json["tools_executed"][0]
            .as_object_mut()
            .unwrap()
            .remove("podman_trace");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("scan_1000000000000000030.json"),
            serde_json::to_string_pretty(&legacy_json).unwrap(),
        )
        .expect("gravação do registro legado");

        let history = list_scan_logs_from_dir(&dir).expect("listagem deve funcionar");
        assert_eq!(history.records.len(), 1);
        assert!(history.unreadable.is_empty());

        let loaded = load_scan_log_from_file(&history.records[0].file_path)
            .expect("registro de versão anterior deve carregar");
        assert_eq!(loaded.scan_id, "scan_1000000000000000030");
        assert_eq!(loaded.info_count, 0);
        assert!(loaded.decisions.is_empty());
        assert!(loaded.tools_executed[0].podman_trace.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_id_rejects_path_traversal_and_out_of_pattern_values() {
        assert!(is_valid_scan_id("scan_1757000000000000000"));
        for invalid in [
            "../../etc/passwd",
            "scan_../../etc/passwd",
            "scan_",
            "scan_abc",
            "scan_1/../../x",
            "scan_1.json",
            "",
            "SCAN_123",
            "scan_123\n",
        ] {
            assert!(
                !is_valid_scan_id(invalid),
                "id fora do padrão deveria ser rejeitado: {invalid}"
            );
            let error = scan_log_path(invalid).expect_err("id invalido nao pode resolver");
            assert!(
                format!("{error:#}").contains("identificador de execução inválido"),
                "mensagem acionável para {invalid}: {error:#}"
            );
        }

        // Mesmo com o XDG isolado, um id válido resolve dentro de scans_dir().
        let path = scan_log_path("scan_1757000000000000000").expect("id valido resolve");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("scan_1757000000000000000.json")
        );
        assert!(path.starts_with(scans_dir()));
    }
}
