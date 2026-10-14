//! Trilha append-only das ações da IA, gravada enquanto a fase acontece: o log
//! estruturado do scan só é escrito no fim, então uma fase interrompida se perde.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::code_agent::progress::CodeAgentEvent;

#[derive(Debug)]
pub struct AgentAuditTrail {
    path: PathBuf,
    file: Mutex<File>,
    seq: AtomicUsize,
}

/// Fica ao lado de `scans/` para que a trilha e o log sejam apagados juntos.
pub fn agent_trails_dir() -> PathBuf {
    let base = crate::orchestrator::scan_logger::scans_dir()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("agent-trails");
    let _ = std::fs::create_dir_all(&base);
    base
}

impl AgentAuditTrail {
    /// Abre a trilha de um scan em um diretório, criando o arquivo se faltar.
    pub fn open_in(dir: &Path, scan_id: &str) -> Result<Self> {
        std::fs::create_dir_all(dir).context("Falha ao criar diretório da trilha de auditoria")?;
        let path = dir.join(format!("{scan_id}.jsonl"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Falha ao abrir trilha de auditoria em {:?}", path))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            seq: AtomicUsize::new(0),
        })
    }

    /// `None` em vez de erro: trilha que não abre não pode derrubar a varredura.
    pub fn open_default(scan_id: &str) -> Option<Self> {
        Self::open_in(&agent_trails_dir(), scan_id).ok()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, mut record: Value) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if let Value::Object(map) = &mut record {
            map.insert("seq".to_string(), json!(seq));
            map.insert("em".to_string(), json!(chrono::Utc::now().to_rfc3339()));
        }
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        // Descarregada na hora: processo encerrado no meio da fase precisa deixar
        // para trás o que já fez.
        if writeln!(file, "{record}").is_ok() {
            let _ = file.flush();
        }
    }

    pub fn record_event(&self, event: &CodeAgentEvent) {
        let sanitize = crate::utils::redaction::sanitize_text;
        let (fase, evento, detalhe) = match event {
            CodeAgentEvent::Started {
                total_findings,
                project_dir,
            } => (
                "agente de codigo",
                "inicio",
                json!({
                    "achados": total_findings,
                    "projeto": sanitize(project_dir),
                }),
            ),
            CodeAgentEvent::ToolInvoked {
                finding_index,
                iteration,
                tool,
                arguments,
            } => (
                "agente de codigo",
                "ferramenta solicitada",
                json!({
                    "achado": finding_index + 1,
                    "iteracao": iteration,
                    "ferramenta": sanitize(tool),
                    "argumentos": arguments,
                }),
            ),
            CodeAgentEvent::ToolCompleted(record) => (
                "agente de codigo",
                "ferramenta concluida",
                json!({
                    "achado": record.finding_index + 1,
                    "iteracao": record.iteration,
                    "ferramenta": sanitize(&record.tool),
                    "desfecho": sanitize(&record.outcome),
                    "resumo": sanitize(&record.summary),
                }),
            ),
            CodeAgentEvent::FindingFinished {
                finding_index,
                located,
                tool_calls,
            } => (
                "agente de codigo",
                "achado concluido",
                json!({
                    "achado": finding_index + 1,
                    "localizado": located,
                    "chamadas": tool_calls,
                }),
            ),
            CodeAgentEvent::Finished {
                located,
                total,
                unavailable_reason,
            } => (
                "agente de codigo",
                "fim",
                json!({
                    "localizados": located,
                    "total": total,
                    "motivo": unavailable_reason
                        .as_deref()
                        .map(crate::utils::redaction::sanitize_diagnostic),
                }),
            ),
        };
        self.write(json!({ "fase": fase, "evento": evento, "detalhe": detalhe }));
    }

    /// Antes de chamar o provedor, para a auditoria distinguir "a IA estava
    /// pensando" de "a IA não chegou a ser chamada".
    pub fn record_analysis_started(&self, provider: &str, model: &str, findings: usize) {
        self.write(json!({
            "fase": "analise de achados",
            "evento": "inicio",
            "detalhe": {
                "provedor": crate::utils::redaction::sanitize_text(provider),
                "modelo": crate::utils::redaction::sanitize_text(model),
                "achados": findings,
            },
        }));
    }

    /// Inclusive quando o texto não veio do modelo configurado.
    pub fn record_analysis_finished(&self, result: &crate::ai::analysis_service::AnalysisResult) {
        self.write(json!({
            "fase": "analise de achados",
            "evento": "fim",
            "detalhe": {
                "provedor_efetivo": crate::utils::redaction::sanitize_text(&result.provider),
                "modelo": crate::utils::redaction::sanitize_text(&result.model),
                "provedor_configurado":
                    crate::utils::redaction::sanitize_text(&result.configured_provider),
                "origem": format!("{:?}", result.source),
                "alternativa_usada": result.fallback_used,
                "motivo_da_falha": result
                    .failure_reason
                    .as_deref()
                    .map(crate::utils::redaction::sanitize_diagnostic),
                "trechos_neutralizados": result.neutralized_snippets,
            },
        }));
    }
}

/// Linha truncada pela queda do processo não pode impedir a leitura do resto.
pub fn read_records(path: &Path) -> Result<Vec<Value>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Falha ao ler trilha de auditoria em {:?}", path))?;
    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_agent::agent::ToolCallRecord;

    fn trilha_em_temp(dir: &Path) -> AgentAuditTrail {
        AgentAuditTrail::open_in(dir, "scan_teste").expect("trilha temporária")
    }

    #[test]
    fn cada_acao_da_ia_vira_uma_linha_na_ordem_em_que_ocorreu() {
        let dir = std::env::temp_dir().join(format!("ss-trilha-ordem-{}", std::process::id()));
        let trail = trilha_em_temp(&dir);

        trail.record_event(&CodeAgentEvent::Started {
            total_findings: 2,
            project_dir: "/tmp/projeto".to_string(),
        });
        trail.record_event(&CodeAgentEvent::ToolCompleted(ToolCallRecord {
            finding_index: 0,
            iteration: 0,
            tool: "read_file".to_string(),
            arguments: "{\"path\":\"app.py\"}".to_string(),
            outcome: "ok".to_string(),
            summary: "200 linhas".to_string(),
        }));

        let registros = read_records(trail.path()).expect("leitura da trilha");
        assert_eq!(registros.len(), 2);
        assert_eq!(registros[0]["evento"], "inicio");
        assert_eq!(registros[1]["evento"], "ferramenta concluida");
        assert_eq!(registros[1]["detalhe"]["ferramenta"], "read_file");
        assert_eq!(
            registros
                .iter()
                .map(|r| r["seq"].clone())
                .collect::<Vec<_>>(),
            vec![json!(1), json!(2)]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_trilha_registra_a_fase_mesmo_sem_nenhuma_intervencao_da_interface() {
        let dir = std::env::temp_dir().join(format!("ss-trilha-headless-{}", std::process::id()));
        let trail = trilha_em_temp(&dir);

        trail.record_analysis_started("NVIDIA NIM", "nvidia/nemotron-3-super-120b-a12b", 4);

        let registros = read_records(trail.path()).expect("leitura da trilha");
        assert_eq!(registros[0]["fase"], "analise de achados");
        assert_eq!(registros[0]["detalhe"]["provedor"], "NVIDIA NIM");
        assert_eq!(registros[0]["detalhe"]["achados"], 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn o_motivo_da_falha_da_ia_sobrevive_no_registro() {
        let dir = std::env::temp_dir().join(format!("ss-trilha-falha-{}", std::process::id()));
        let trail = trilha_em_temp(&dir);
        let resultado = crate::ai::analysis_service::AnalysisResult {
            text: "texto".to_string(),
            model: String::new(),
            provider: "Nenhuma".to_string(),
            configured_provider: "OpenAI".to_string(),
            source: crate::ai::analysis_service::AnalysisSource::Deterministic,
            fallback_used: false,
            failure_reason: Some("tempo limite de 45 s excedido".to_string()),
            analyzed_at: "2026-01-01T00:00:00Z".to_string(),
            neutralized_snippets: 2,
        };

        trail.record_analysis_finished(&resultado);

        let registros = read_records(trail.path()).expect("leitura da trilha");
        assert_eq!(registros[0]["evento"], "fim");
        assert_eq!(registros[0]["detalhe"]["provedor_efetivo"], "Nenhuma");
        assert_eq!(
            registros[0]["detalhe"]["motivo_da_falha"],
            "tempo limite de 45 s excedido"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uma_linha_truncada_nao_esconde_o_que_ja_foi_gravado() {
        let dir = std::env::temp_dir().join(format!("ss-trilha-trunc-{}", std::process::id()));
        let trail = trilha_em_temp(&dir);
        trail.record_event(&CodeAgentEvent::Finished {
            located: 1,
            total: 1,
            unavailable_reason: None,
        });
        // Simula a queda no meio da escrita da linha seguinte.
        let mut conteudo = std::fs::read_to_string(trail.path()).unwrap();
        conteudo.push_str("{\"seq\":2,\"fase\":\"agente de co");
        std::fs::write(trail.path(), conteudo).unwrap();

        let registros = read_records(trail.path()).expect("leitura tolerante");
        assert_eq!(registros.len(), 1);
        assert_eq!(registros[0]["evento"], "fim");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uma_trilha_que_nao_pode_ser_criada_nao_interrompe_a_varredura() {
        let dir = std::env::temp_dir().join(format!("ss-trilha-bloqueio-{}", std::process::id()));
        // Um caminho regular no lugar do diretório faz `create_dir_all` falhar.
        std::fs::write(&dir, b"nao sou um diretorio").unwrap();

        assert!(AgentAuditTrail::open_in(&dir, "scan_teste").is_err());
        assert!(AgentAuditTrail::open_default("scan_teste").is_some());

        std::fs::remove_file(&dir).ok();
    }
}
