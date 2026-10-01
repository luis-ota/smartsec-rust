use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::utils::redaction::sanitize_evidence_component;
use serde::Deserialize;
use std::collections::HashSet;

/// ID do Nikto que indica que nenhum servidor web respondeu no alvo.
///
/// O Nikto termina com exit status 0 nesse caso, então o item precisa ser
/// reconhecido como diagnóstico pelo próprio ID, sem procurar por texto.
const ID_SEM_SERVIDOR_WEB: &str = "000029";

/// Título e evidência são limitados para caber no relatório sem truncar a
/// informação essencial do achado.
const TITLE_LIMIT: usize = 120;
const EVIDENCE_LIMIT: usize = 300;

/// Relatório JSON do Nikto para um host.
///
/// Os campos de identificação do host são opcionais porque, quando nenhum
/// servidor web responde, o Nikto emite um objeto de achado avulso em vez do
/// relatório completo.
#[derive(Deserialize, Debug)]
struct NiktoReport {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<NiktoItem>,
    /// Preenchido apenas quando o objeto é um achado avulso, isto é, quando o
    /// Nikto não encontrou servidor web e não emitiu relatório por host.
    #[serde(default)]
    id: Option<String>,
}

/// Achado individual do relatório JSON do Nikto.
#[derive(Deserialize, Debug)]
struct NiktoItem {
    /// Identificador do teste na taxonomia do Nikto.
    #[serde(default)]
    id: Option<String>,
    /// Referência OSVDB. O Nikto escreve `"0"` quando não há referência.
    #[serde(default, rename = "OSVDB")]
    osvdb: Option<String>,
    /// Método HTTP usado no teste.
    #[serde(default)]
    method: Option<String>,
    /// Caminho testado, relativo ao host.
    #[serde(default)]
    url: Option<String>,
    /// Descrição do achado produzido pelo Nikto.
    #[serde(default)]
    msg: Option<String>,
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let mut truncated: String = value.chars().take(limit).collect();
    truncated.push('…');
    truncated
}

/// Constrói a URL absoluta a partir do alvo e do caminho devolvido pelo Nikto.
///
/// O Nikto reporta o caminho testado (`/admin/`). Preservar a URL absoluta é
/// o que torna o achado acionável, e a query string é removida pela
/// sanitização.
fn absolute_url(target: &str, path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return target.to_string();
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base = target.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Traduz a taxonomia de IDs do Nikto para a severidade do SmartSec.
///
/// O Nikto não emite um campo `severity`: a informação estruturada que ele
/// publica é a faixa do ID do teste, que separa as categorias do scanner
/// (`db_tests`, `db_outdated`, `db_realms`, `db_server_msgs`,
/// `db_httpoptions`, `db_embedded`), e a referência OSVDB. A faixa do scanner é
/// a fonte autoritativa e por isso define a severidade, sem interpretar o
/// texto da mensagem.
fn severity_for(id: &str, osvdb: &str) -> Severity {
    if has_osvdb_reference(osvdb) {
        return Severity::High;
    }
    let Some(digit) = id.chars().next() else {
        return Severity::Info;
    };
    match digit {
        // `db_embedded`, `db_httpoptions` e `db_dir_traversal`: exposição
        // técnica que exige verificação antes de virar correção.
        '3' | '4' | '5' => Severity::Medium,
        // `db_outdated`: software desatualizado, risco real de exploração.
        '6' => Severity::Medium,
        // `db_realms` e `db_content_search`: information disclosure.
        '7' | '8' => Severity::Low,
        // `db_tests` e os IDs gerados pelos plugins de cabeçalho e robots:
        // misconfiguração e hardening.
        _ => Severity::Low,
    }
}

/// O Nikto escreve `OSVDB: "0"` quando o teste não tem referência OSVDB.
fn has_osvdb_reference(osvdb: &str) -> bool {
    let trimmed = osvdb.trim();
    !trimmed.is_empty() && trimmed != "0" && trimmed != "-1"
}

fn is_diagnostic_id(id: &str) -> bool {
    id == ID_SEM_SERVIDOR_WEB
}

fn reference_for(id: &str, osvdb: &str) -> String {
    let mut reference = format!("nikto:{id}");
    if has_osvdb_reference(osvdb) {
        reference.push_str(&format!(" osvdb:{osvdb}"));
    }
    reference
}

/// Parseia a saída JSON do Nikto e retorna achados reais com proveniência
/// completa.
///
/// URL, método HTTP, referência (ID do Nikto e OSVDB) e evidência são
/// preservados. Itens que o Nikto classifica como diagnóstico não viram
/// vulnerabilidade: eles são devolvidos como erro de execução.
#[allow(dead_code)]
pub fn parse_nikto_findings(json_output: &str, target: &str) -> Vec<Vulnerability> {
    parse_nikto_findings_with_errors(json_output, target).0
}

/// Retorna os achados e os erros do relatório. JSON inválido nunca é tratado
/// como varredura limpa e silenciosa.
pub fn parse_nikto_findings_with_errors(
    json_output: &str,
    target: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let trimmed = json_output.trim();
    if trimmed.is_empty() || trimmed.starts_with("[ERRO]") {
        return (
            Vec::new(),
            vec![
                "o Nikto não produziu relatório JSON; a execução precisa ser revisada".to_string(),
            ],
        );
    }

    let report: NiktoReport = match serde_json::from_str(trimmed) {
        Ok(report) => report,
        Err(error) => return (Vec::new(), vec![format!("JSON do Nikto inválido: {error}")]),
    };

    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let detected_at = now_iso8601();

    let banner = report.banner.unwrap_or_default();
    let host = report
        .host
        .or(report.ip)
        .unwrap_or_else(|| target.to_string());
    let port = report.port.unwrap_or_default();

    // Quando nenhum servidor web responde, o Nikto emite o achado avulso no
    // topo do JSON em vez do relatório por host.
    if let Some(id) = report.id.as_deref() {
        errors.push(diagnostic_message(id, &host, &port));
        return (findings, errors);
    }

    for item in report.vulnerabilities {
        let id = item.id.unwrap_or_default();
        if id.trim().is_empty() {
            errors.push("achado do Nikto sem identificador de teste foi descartado".to_string());
            continue;
        }
        if is_diagnostic_id(&id) {
            errors.push(diagnostic_message(&id, &host, &port));
            continue;
        }

        let osvdb = item.osvdb.unwrap_or_default();
        let method = item.method.unwrap_or_default();
        let path = item.url.unwrap_or_default();
        let message = item.msg.unwrap_or_default();

        let dedup_key = format!("{}\u{1f}{}\u{1f}{}\u{1f}{}", id, method, path, message);
        if !seen.insert(dedup_key) {
            continue;
        }

        let severity = severity_for(&id, &osvdb);
        let url = absolute_url(target, &path);
        let method_label = if method.trim().is_empty() {
            "não especificado"
        } else {
            method.trim()
        };
        let reference = reference_for(id.trim(), osvdb.trim());
        let detail = if message.trim().is_empty() {
            "o Nikto não descreveu o achado".to_string()
        } else {
            truncate(message.trim(), EVIDENCE_LIMIT)
        };

        let title = format!("Achado Nikto {reference} — {detail}");
        let description = format!(
            "O teste {reference} do Nikto foi acionado pelo método {method_label} em {url}. Detalhe informado pelo scanner: {detail}"
        );
        let recommendation = format!(
            "Confirme o achado no endpoint {url}, aplique a correção pertinente ao servidor e repita a varredura."
        );
        let didactic = format!(
            "O Nikto identificou o teste {reference} no método {method_label}.\n\nSeveridade atribuída a partir da categoria do teste e da referência do scanner: {}\nEndpoint: {url}\n\nO achado vem de uma varredura ativa de configuração de servidor web. Confirme a evidência no ambiente autorizado antes de tratar como vulnerabilidade corrigível.",
            severity.label_pt_br(),
        );

        let safe_url = sanitize_evidence_component(&url);
        let safe_method = sanitize_evidence_component(method_label);
        let safe_reference = sanitize_evidence_component(&reference);
        let safe_host = sanitize_evidence_component(&host);
        let safe_banner = sanitize_evidence_component(if banner.is_empty() {
            "não informado"
        } else {
            &banner
        });
        let safe_message = sanitize_evidence_component(&detail);

        findings.push(Vulnerability {
            title: truncate(&title, TITLE_LIMIT),
            severity,
            description,
            tool: "Nikto".to_string(),
            recommendation,
            didactic,
            source: FindingSource::Real,
            target: target.to_string(),
            evidence: format!(
                "nikto referência: {safe_reference} | método: {safe_method} | url: {safe_url} | host: {safe_host} | banner: {safe_banner} | msg: {safe_message}"
            ),
            detected_at: detected_at.clone(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,

            // Scanner não conhece o código do projeto: a origem no código é
            // preenchida exclusivamente pela fase do agente de código (#76).
            code_location: None,
            code_remediation: Vec::new(),
        });
    }

    (findings, errors)
}

fn diagnostic_message(id: &str, host: &str, port: &str) -> String {
    let endpoint = if port.is_empty() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    format!(
        "o Nikto não encontrou servidor web no alvo {endpoint} (código interno {id}); verifique se o serviço responde e está autorizado para a varredura"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::nikto::container_arguments;

    const REAL: &str = include_str!("../../tests/fixtures/nikto/relatorio.json");
    const SEM_SERVIDOR: &str = include_str!("../../tests/fixtures/nikto/sem_servidor.json");
    const INVALIDO: &str = include_str!("../../tests/fixtures/nikto/invalido.json");
    const DUPLICADO: &str = include_str!("../../tests/fixtures/nikto/duplicado.json");

    const TARGET: &str = "http://169.254.1.2:3000";

    #[test]
    fn preserva_url_metodo_referencia_e_evidencia() {
        let (findings, errors) = parse_nikto_findings_with_errors(REAL, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 5);

        let finding = &findings[0];
        assert_eq!(finding.tool, "Nikto");
        assert_eq!(finding.source, FindingSource::Real);
        assert_eq!(finding.target, TARGET);

        // URL absoluta reconstruída a partir do caminho do Nikto.
        assert!(
            finding.evidence.contains("url: http://169.254.1.2:3000/"),
            "{}",
            finding.evidence
        );
        // Método HTTP preservado.
        assert!(
            finding.evidence.contains("método: GET"),
            "{}",
            finding.evidence
        );
        // Referência preservada.
        assert!(
            finding.evidence.contains("referência: nikto:999957"),
            "{}",
            finding.evidence
        );
        // Evidência preservada.
        assert!(
            finding
                .evidence
                .contains("msg: The anti-clickjacking X-Frame-Options header is not present."),
            "{}",
            finding.evidence
        );
        // Banner do servidor preservado.
        assert!(
            finding
                .evidence
                .contains("banner: SimpleHTTP/0.6 Python/3.14.7"),
            "{}",
            finding.evidence
        );
    }

    #[test]
    fn preserva_o_metodo_head_dos_testes_de_software_desatualizado() {
        let (findings, _) = parse_nikto_findings_with_errors(REAL, TARGET);

        let outdated = findings
            .iter()
            .find(|finding| finding.evidence.contains("nikto:600720"))
            .expect("o teste de software desatualizado deve ser preservado");

        assert!(
            outdated.evidence.contains("método: HEAD"),
            "{}",
            outdated.evidence
        );
        assert!(outdated
            .evidence
            .contains("SimpleHTTP/0.6 appears to be outdated"));
    }

    #[test]
    fn referencia_osvdb_e_preservada_e_eleva_a_severidade() {
        let (findings, errors) = parse_nikto_findings_with_errors(DUPLICADO, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let with_osvdb = findings
            .iter()
            .find(|finding| finding.evidence.contains("osvdb:"))
            .expect("o item com OSVDB deve ser preservado");

        assert!(
            with_osvdb.evidence.contains("nikto:009004 osvdb:1234"),
            "{}",
            with_osvdb.evidence
        );
        assert_eq!(with_osvdb.severity, Severity::High);
    }

    #[test]
    fn osvdb_zero_nao_conta_como_referencia() {
        assert!(!has_osvdb_reference("0"));
        assert!(!has_osvdb_reference(""));
        assert!(has_osvdb_reference("1234"));
    }

    #[test]
    fn severidade_vem_da_taxonomia_de_ids_do_scanner() {
        // db_outdated (software desatualizado).
        assert_eq!(severity_for("600720", "0"), Severity::Medium);
        // db_embedded / db_httpoptions / db_dir_traversal.
        assert_eq!(severity_for("400001", "0"), Severity::Medium);
        // db_tests e IDs de plugin (misconfiguração e hardening).
        assert_eq!(severity_for("999957", "0"), Severity::Low);
        // db_server_msgs (information disclosure).
        assert_eq!(severity_for("800001", "0"), Severity::Low);
        // Referência OSVDB prevalece sobre a faixa.
        assert_eq!(severity_for("000001", "4321"), Severity::High);
        // ID ausente não pode gerar achado crítico.
        assert_eq!(severity_for("", "0"), Severity::Info);
    }

    #[test]
    fn alvo_sem_servidor_web_vira_erro_e_nao_vulnerabilidade() {
        let (findings, errors) = parse_nikto_findings_with_errors(SEM_SERVIDOR, TARGET);

        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("não encontrou servidor web"),
            "{errors:?}"
        );
        // Sem host/port no JSON, o erro aponta para o alvo informado na CLI.
        assert!(errors[0].contains(TARGET), "{errors:?}");
        assert!(errors[0].contains("000029"), "{errors:?}");
    }

    #[test]
    fn json_invalido_e_reportado_em_vez_de_varrer_limpo() {
        let (findings, errors) = parse_nikto_findings_with_errors(INVALIDO, TARGET);

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("JSON do Nikto inválido"), "{errors:?}");
    }

    #[test]
    fn saida_vazia_ou_diagnostica_e_reportada() {
        for output in ["", "   ", "[ERRO] Podman falhou"] {
            let (findings, errors) = parse_nikto_findings_with_errors(output, TARGET);

            assert!(findings.is_empty(), "{output:?}");
            assert_eq!(errors.len(), 1, "{output:?}");
            assert!(
                errors[0].contains("não produziu relatório JSON"),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn deduplica_achados_repetidos() {
        let (findings, errors) = parse_nikto_findings_with_errors(DUPLICADO, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let keys: HashSet<&str> = findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect();
        assert_eq!(
            keys.len(),
            findings.len(),
            "achados duplicados sobreviveram"
        );
    }

    #[test]
    fn evidencia_exclui_corpos_http_credenciais_e_query_string() {
        let raw = r#"{"host":"alvo.local","ip":"alvo.local","port":"80","banner":"nginx","vulnerabilities":[{"id":"999100","OSVDB":"0","method":"GET","url":"/admin?token=segredo","msg":"cookie: session=segredo"}]}"#;

        let (findings, _) = parse_nikto_findings_with_errors(raw, "http://alvo.local");

        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert!(evidence.contains("nikto:999100"), "{evidence}");
        assert!(
            evidence.contains("url: http://alvo.local/admin"),
            "{evidence}"
        );
        assert!(!evidence.contains("token="), "{evidence}");
        assert!(!evidence.contains("segredo"), "{evidence}");
        assert!(!evidence.contains("request"), "{evidence}");
        assert!(!evidence.contains("response"), "{evidence}");
    }

    #[test]
    fn constroi_url_absoluta_para_caminhos_relativos_e_absolutos() {
        assert_eq!(
            absolute_url("http://alvo.local:3000", "/admin/"),
            "http://alvo.local:3000/admin/"
        );
        assert_eq!(
            absolute_url("http://alvo.local:3000", "admin/"),
            "http://alvo.local:3000/admin/"
        );
        assert_eq!(
            absolute_url("http://alvo.local:3000/", "/admin/"),
            "http://alvo.local:3000/admin/"
        );
        assert_eq!(
            absolute_url("http://alvo.local:3000", "https://outro.local/x"),
            "https://outro.local/x"
        );
        assert_eq!(
            absolute_url("http://alvo.local:3000", ""),
            "http://alvo.local:3000"
        );
    }

    #[test]
    fn achado_sem_id_e_descartado_com_erro() {
        let raw = r#"{"host":"alvo.local","vulnerabilities":[{"msg":"sem identificador"}]}"#;

        let (findings, errors) = parse_nikto_findings_with_errors(raw, "http://alvo.local");

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("sem identificador de teste"),
            "{errors:?}"
        );
    }

    #[test]
    fn metodo_e_url_ausentes_nao_quebram_o_achado() {
        let raw = r#"{"host":"alvo.local","vulnerabilities":[{"id":"999100","OSVDB":"0","msg":"achado sem método nem caminho"}]}"#;

        let (findings, errors) = parse_nikto_findings_with_errors(raw, "http://alvo.local");

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].evidence.contains("método: não especificado"),
            "{findings:?}"
        );
        assert!(
            findings[0].evidence.contains("url: http://alvo.local"),
            "{findings:?}"
        );
    }

    #[test]
    fn mensagens_longas_sao_truncadas_sem_quebrar_o_json() {
        let raw = format!(
            r#"{{"host":"alvo.local","vulnerabilities":[{{"id":"999100","OSVDB":"0","method":"GET","url":"/","msg":"{}"}}]}}"#,
            "x".repeat(1000)
        );

        let (findings, errors) = parse_nikto_findings_with_errors(&raw, "http://alvo.local");

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.chars().count() < 700);
    }

    #[test]
    fn o_manifesto_usa_o_comando_validado_no_container() {
        let arguments = container_arguments(TARGET);

        // O modo JSON precisa escrever no stdout, sem shell e sem arquivo.
        assert!(arguments.windows(2).any(|pair| pair == ["-Format", "json"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-o", "-"]));
        // O prompt do CIRT.net contaminaria o JSON se fosse habilitado.
        assert!(arguments.windows(2).any(|pair| pair == ["-ask", "no"]));
        assert!(arguments
            .iter()
            .any(|argument| argument == "-nointeractive"));
        assert!(arguments.iter().any(|argument| argument == TARGET));
    }
}
