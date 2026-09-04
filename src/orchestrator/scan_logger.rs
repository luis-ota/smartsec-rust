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
            target_url,
            started_at,
            completed_at,
            execution_type,
            llm_provider,
            tools_executed,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            findings: findings
                .iter()
                .map(|finding| serde_json::to_value(finding).unwrap_or(serde_json::Value::Null))
                .collect(),
            agent_analysis,
            decisions: Vec::new(),
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
    let filename = format!("{}.json", metadata.scan_id);
    let path = target_dir.join(filename);

    let json_data = serde_json::to_string_pretty(metadata)
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
        let legacy: ScanMetadata = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(legacy.info_count, 0);

        let path = save_scan_log_to_dir(&metadata, &temp_dir).expect("save should succeed");
        assert!(path.exists());

        let loaded = load_scan_log_from_file(&path).expect("load should succeed");
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
}
