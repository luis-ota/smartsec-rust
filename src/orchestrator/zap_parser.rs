use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::utils::redaction::sanitize_evidence_component;
use serde::Deserialize;
use std::collections::HashSet;

/// Título e evidência são limitados para caber no relatório sem truncar a
/// informação essencial do achado.
const TITLE_LIMIT: usize = 120;
const EVIDENCE_LIMIT: usize = 300;

/// Quantidade máxima de instâncias preservadas por alerta.
///
/// O ZAP agrupa todas as URLs que dispararam o mesmo alerta em um único item com
/// um array `instances`. Só as primeiras instâncias entram na evidência, para
/// que um alerta repetido em centenas de URLs não inunde o relatório.
const INSTANCE_LIMIT: usize = 3;

/// Relatório JSON `traditional-json` do ZAP.
#[derive(Deserialize, Debug)]
struct ZapReport {
    #[serde(default, rename = "site")]
    sites: Vec<ZapSite>,
}

/// Um site (host/porta) varrido pelo ZAP.
#[derive(Deserialize, Debug)]
struct ZapSite {
    #[serde(default, rename = "@name")]
    name: Option<String>,
    #[serde(default, rename = "@host")]
    host: Option<String>,
    #[serde(default, rename = "@port")]
    port: Option<String>,
    #[serde(default)]
    alerts: Vec<ZapAlert>,
}

/// Alerta do ZAP, agrupado por regra do add-on.
#[derive(Deserialize, Debug)]
struct ZapAlert {
    /// Identificador numérico da regra do add-on.
    #[serde(default)]
    pluginid: Option<String>,
    /// Referência da regra, com sufixo de variação quando aplicável.
    #[serde(default, rename = "alertRef")]
    alertref: Option<String>,
    /// Nome do alerta.
    #[serde(default)]
    alert: Option<String>,
    /// Risco estruturado do scanner: `0` informativa, `1` baixa, `2` média,
    /// `3` alta. É a severidade autoritativa do ZAP.
    #[serde(default)]
    riskcode: Option<String>,
    /// Confiança do scanner, separada do risco.
    #[serde(default)]
    confidence: Option<String>,
    /// Risco e confiança rotulados pelo próprio scanner (ex.: `Medium (High)`).
    #[serde(default)]
    riskdesc: Option<String>,
    /// CWE associado à regra.
    #[serde(default)]
    cweid: Option<String>,
    /// Solução recomendada pelo ZAP, em HTML.
    #[serde(default)]
    solution: Option<String>,
    /// URLs que dispararam o alerta.
    #[serde(default)]
    instances: Vec<ZapInstance>,
}

/// Instância do alerta: uma URL e o método que a dispararam.
#[derive(Deserialize, Debug)]
struct ZapInstance {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    method: Option<String>,
    /// Nome do parâmetro ou cabeçalho observado na evidência do alerta.
    #[serde(default)]
    param: Option<String>,
    /// Trecho de evidência retornado pelo servidor (ex.: valor de banner).
    #[serde(default)]
    evidence: Option<String>,
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

/// Traduz o campo `riskcode` do ZAP para a severidade do SmartSec.
///
/// A severidade do scanner é autoritativa (TCC_SPEC §7) e não é reinterpretada a
/// partir do texto de `desc`/`riskdesc`: o ZAP publica um risco estruturado
/// próprio, de `0` a `3`, e é dele que a classificação vem. O ZAP não tem o nível
/// `Crítico` da taxonomia do SmartSec, então o risco alto é o teto. Um
/// `riskcode` ausente ou fora da faixa vira `Info` em vez de ser elevado, para
/// que uma saída inesperada nunca produza severidade maior do que a do scanner.
fn severity_for_risk(riskcode: &str) -> Severity {
    match riskcode.trim() {
        "3" => Severity::High,
        "2" => Severity::Medium,
        "1" => Severity::Low,
        "0" => Severity::Info,
        _ => Severity::Info,
    }
}

/// Converte a numeração de confiança do ZAP no rótulo em português.
fn confidence_label(confidence: &str) -> &'static str {
    match confidence.trim() {
        "4" => "confirmada",
        "3" => "alta",
        "2" => "média",
        "1" => "baixa",
        _ => "não informada",
    }
}

/// Extrai o texto de um campo do ZAP escrito em HTML.
///
/// Os campos `desc` e `solution` chegam como HTML do wiki do ZAP. O texto puro é
/// suficiente para a descrição e a recomendação, e evita marcar o relatório com
/// marcação vinda de fonte externa.
fn html_to_text(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    let mut inside_tag = false;
    for character in value.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => text.push(character),
            _ => {}
        }
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Referência estável do achado: regra do add-on, variação e CWE.
fn reference_for(alert: &ZapAlert) -> String {
    let mut reference = match (alert.alertref.as_deref(), alert.pluginid.as_deref()) {
        (Some(alert_ref), _) if !alert_ref.trim().is_empty() => {
            format!("zap:{alert_ref}")
        }
        (_, Some(plugin)) if !plugin.trim().is_empty() => format!("zap:plugin:{plugin}"),
        _ => "zap:alerta sem referência".to_string(),
    };
    if let Some(cwe) = non_empty_opt(alert.cweid.as_deref()) {
        reference.push_str(&format!(" cwe:{cwe}"));
    }
    reference
}

/// Constrói a URL absoluta a partir do alvo e da URI relatada pelo ZAP.
///
/// O ZAP reporta a URL completa (`uri`). Ela é preservada como está, com a
/// query string removida pela sanitização; quando a URI é relativa, é composta
/// com o alvo.
fn absolute_url(target: &str, uri: &str) -> String {
    let uri = uri.trim();
    if uri.is_empty() {
        return target.to_string();
    }
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return uri.to_string();
    }
    let base = target.trim_end_matches('/');
    if uri.starts_with('/') {
        format!("{base}{uri}")
    } else {
        format!("{base}/{uri}")
    }
}

/// Parseia o relatório `traditional-json` do ZAP e retorna achados reais com
/// proveniência completa.
///
/// URL, método HTTP, referência (regra do add-on, variação e CWE) e evidência
/// mínima sanitizada são preservados. O template `traditional-json` não traz
/// cabeçalhos nem corpos de requisição/resposta, e a sanitização remove
/// query strings e credenciais de qualquer campo que sobre.
#[allow(dead_code)]
pub fn parse_zap_findings(json_output: &str, target: &str) -> Vec<Vulnerability> {
    parse_zap_findings_with_errors(json_output, target).0
}

/// Retorna os achados e os erros do relatório. JSON inválido nunca é tratado
/// como varredura limpa e silenciosa.
pub fn parse_zap_findings_with_errors(
    json_output: &str,
    target: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let trimmed = json_output.trim();
    if trimmed.is_empty() || trimmed.starts_with("[ERRO]") {
        return (
            Vec::new(),
            vec!["o ZAP não produziu relatório JSON; a execução precisa ser revisada".to_string()],
        );
    }

    let report: ZapReport = match serde_json::from_str(trimmed) {
        Ok(report) => report,
        Err(error) => return (Vec::new(), vec![format!("JSON do ZAP inválido: {error}")]),
    };

    if report.sites.is_empty() {
        return (
            Vec::new(),
            vec![
                "o relatório do ZAP não contém nenhum site varrido; a varredura não pode ser considerada limpa"
                    .to_string(),
            ],
        );
    }

    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let detected_at = now_iso8601();

    for site in report.sites {
        let host = site.host.clone().unwrap_or_default();
        let port = site.port.clone().unwrap_or_default();
        let site_name = site
            .name
            .or(site.host)
            .unwrap_or_else(|| target.to_string());

        if site.alerts.is_empty() {
            errors.push(format!(
                "o ZAP não encontrou alertas no site {site_name}; confirme que o alvo respondeu à varredura"
            ));
            continue;
        }

        for alert in site.alerts {
            let Some(reference) =
                non_empty_opt(alert.alertref.as_deref()).map(|_| reference_for(&alert))
            else {
                errors.push("alerta do ZAP sem identificador de regra foi descartado".to_string());
                continue;
            };
            let title_text =
                non_empty_opt(alert.alert.as_deref()).unwrap_or("alerta sem descrição");
            let riskcode = alert.riskcode.clone().unwrap_or_default();
            let riskdesc = non_empty_opt(alert.riskdesc.as_deref()).unwrap_or("não informado");
            let severity = severity_for_risk(&riskcode);
            let confidence = confidence_label(&alert.confidence.unwrap_or_default());

            let dedup_key = format!("{}\u{1f}{}", reference, title_text);
            if !seen.insert(dedup_key) {
                continue;
            }

            let instances: Vec<ZapInstance> = if alert.instances.is_empty() {
                vec![ZapInstance {
                    uri: None,
                    method: None,
                    param: None,
                    evidence: None,
                }]
            } else {
                alert.instances
            };
            let urls: Vec<String> = instances
                .iter()
                .take(INSTANCE_LIMIT)
                .map(|instance| absolute_url(target, instance.uri.as_deref().unwrap_or_default()))
                .collect();
            let url = urls.first().cloned().unwrap_or_else(|| target.to_string());
            let method = instances
                .iter()
                .find_map(|instance| non_empty_opt(instance.method.as_deref()))
                .unwrap_or("não especificado")
                .to_string();
            let param = non_empty_opt(instances[0].param.as_deref()).unwrap_or("não informado");
            let scanner_evidence = non_empty_opt(instances[0].evidence.as_deref())
                .map(html_to_text)
                .map(|value| truncate(&value, EVIDENCE_LIMIT))
                .unwrap_or_else(|| "não informada".to_string());
            let extra_urls = urls.len().saturating_sub(1);
            let total_instances = instances.len();

            let solution = alert
                .solution
                .as_deref()
                .map(html_to_text)
                .filter(|value| !value.is_empty())
                .map(|value| truncate(&value, EVIDENCE_LIMIT))
                .unwrap_or_else(|| {
                    "consulte a documentação da regra do ZAP para a correção".to_string()
                });

            let endpoint_label = site_endpoint(&site_name, &host, &port);
            let title = format!("ZAP {reference} — {title_text}");
            let description = format!(
                "O ZAP detectou a regra {reference} ({title_text}) em {endpoint_label}, com risco e confiança do scanner \"{riskdesc}\" e confiança {confidence}. Instâncias: {total_instances} (método {method}). Evidência devolvida pelo alvo: {scanner_evidence}"
            );
            let recommendation = format!(
                "Aplique a correção indicada pelo ZAP: {solution} Verifique o efeito em {url} e repita a varredura."
            );
            let didactic = format!(
                "O ZAP encontrou um alerta de risco {riskdesc} no site {endpoint_label}.\n\nO que significa: o scanner identificou a condição \"{title_text}\" ao investigar a aplicação. Confiança {confidence} indica o quanto o ZAP considera o achado firme.\n\nO que fazer: {solution}\n\nComo o alerta é agrupado por regra, as {total_instances} instâncias podem estar em URLs diferentes do mesmo site. Confirme cada URL em um ambiente autorizado antes de tratar como vulnerabilidade corrigível."
            );

            let safe_url = sanitize_evidence_component(&url);
            let safe_reference = sanitize_evidence_component(&reference);
            let safe_method = sanitize_evidence_component(&method);
            let safe_param = sanitize_evidence_component(param);
            let safe_host =
                sanitize_evidence_component(if host.is_empty() { &site_name } else { &host });
            let safe_scanner_evidence = sanitize_evidence_component(&scanner_evidence);
            let safe_title = sanitize_evidence_component(title_text);
            let mut evidence = format!(
                "zap referência: {safe_reference} | alerta: {safe_title} | método: {safe_method} | url: {safe_url} | host: {safe_host} | risco: {riskdesc} | confiança: {confidence} | parâmetro: {safe_param} | evidência: {safe_scanner_evidence}"
            );
            if extra_urls > 0 {
                let other_urls = urls[1..]
                    .iter()
                    .map(|value| sanitize_evidence_component(value))
                    .collect::<Vec<_>>()
                    .join(", ");
                evidence.push_str(&format!(" | outras URLs: {other_urls}"));
            }
            if total_instances > urls.len() {
                evidence.push_str(&format!(
                    " |_instances omitidas: {}",
                    total_instances - urls.len()
                ));
            }

            findings.push(Vulnerability {
                title: truncate(&title, TITLE_LIMIT),
                severity,
                description,
                tool: "ZAP".to_string(),
                recommendation,
                didactic,
                source: FindingSource::Real,
                target: target.to_string(),
                evidence,
                detected_at: detected_at.clone(),
                origins: Vec::new(),
                enrichment: None,
                severity_conflict: None,
                code_location: None,
                code_remediation: Vec::new(),
            });
        }
    }

    (findings, errors)
}

/// Monta o `host:porta` legível do site varrido, sem repetir scheme/host.
fn site_endpoint(site_name: &str, host: &str, port: &str) -> String {
    if !host.is_empty() && !port.is_empty() {
        return format!("{host}:{port}");
    }
    site_name.to_string()
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Atalho de [`non_empty`] para campos opcionais do JSON do ZAP.
fn non_empty_opt(value: Option<&str>) -> Option<&str> {
    non_empty(value.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = include_str!("../../tests/fixtures/zap/relatorio.json");
    const INVALIDO: &str = include_str!("../../tests/fixtures/zap/invalido.json");
    const DUPLICADO: &str = include_str!("../../tests/fixtures/zap/duplicado.json");

    const TARGET: &str = "http://169.254.1.2:3000";

    #[test]
    fn preserva_url_metodo_referencia_e_evidencia() {
        let (findings, errors) = parse_zap_findings_with_errors(REAL, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 4);

        let finding = &findings[0];
        assert_eq!(finding.tool, "ZAP");
        assert_eq!(finding.source, FindingSource::Real);
        assert_eq!(finding.target, TARGET);

        assert!(
            finding.evidence.contains("url: http://169.254.1.2:3000/"),
            "{}",
            finding.evidence
        );
        assert!(
            finding.evidence.contains("método: GET"),
            "{}",
            finding.evidence
        );
        assert!(
            finding.evidence.contains("referência: zap:10038-1"),
            "{}",
            finding.evidence
        );
        assert!(
            finding
                .evidence
                .contains("Content Security Policy (CSP) Header Not Set"),
            "{}",
            finding.evidence
        );
        assert!(finding.evidence.contains("cwe:693"), "{}", finding.evidence);
    }

    #[test]
    fn preserva_a_evidencia_devolvida_pelo_alvo() {
        let (findings, _) = parse_zap_findings_with_errors(REAL, TARGET);

        let version = findings
            .iter()
            .find(|finding| finding.evidence.contains("zap:10036"))
            .expect("o alerta de banner deve estar presente");

        assert!(
            version
                .evidence
                .contains("evidência: SimpleHTTP/0.6 Python/3.14.7"),
            "{}",
            version.evidence
        );
    }

    #[test]
    fn preserva_o_parametro_observado_pelo_alerta() {
        let (findings, _) = parse_zap_findings_with_errors(REAL, TARGET);

        let clickjacking = findings
            .iter()
            .find(|finding| finding.evidence.contains("zap:10020"))
            .expect("o alerta de clickjacking deve estar presente");

        assert!(
            clickjacking.evidence.contains("parâmetro: x-frame-options"),
            "{}",
            clickjacking.evidence
        );
    }

    #[test]
    fn a_severidade_vem_do_riskcode_do_scanner() {
        let (findings, _) = parse_zap_findings_with_errors(REAL, TARGET);

        let by_reference = |reference: &str| {
            findings
                .iter()
                .find(|finding| finding.evidence.contains(reference))
                .unwrap_or_else(|| panic!("alerta {reference} ausente"))
                .severity
        };

        // riskcode 2 → Média, independente do texto do alerta.
        assert_eq!(by_reference("zap:10038"), Severity::Medium);
        assert_eq!(by_reference("zap:10020"), Severity::Medium);
        // riskcode 1 → Baixa.
        assert_eq!(by_reference("zap:10036"), Severity::Low);
        assert_eq!(by_reference("zap:10021"), Severity::Low);
    }

    #[test]
    fn a_severidade_nunca_e_elevada_acima_do_risco_do_scanner() {
        assert_eq!(severity_for_risk("3"), Severity::High);
        assert_eq!(severity_for_risk("2"), Severity::Medium);
        assert_eq!(severity_for_risk("1"), Severity::Low);
        assert_eq!(severity_for_risk("0"), Severity::Info);
        // Risco ausente, inválido ou acima da faixa cai no piso, nunca no teto.
        for riskcode in ["", "9", "media", "-1"] {
            assert_eq!(
                severity_for_risk(riskcode),
                Severity::Info,
                "riskcode {riskcode:?} não pode gerar severidade alta"
            );
        }
    }

    #[test]
    fn preserva_o_risco_e_a_confianca_rotulados_pelo_scanner() {
        let (findings, _) = parse_zap_findings_with_errors(REAL, TARGET);

        let csp = &findings[0];
        assert!(
            csp.evidence.contains("risco: Medium (High)"),
            "{}",
            csp.evidence
        );
        assert!(csp.evidence.contains("confiança: alta"), "{}", csp.evidence);
        // Risco e confiança são campos distintos do ZAP.
        let other = &findings[1];
        assert!(
            other.evidence.contains("risco: Medium (Medium)"),
            "{}",
            other.evidence
        );
        assert!(
            other.evidence.contains("confiança: média"),
            "{}",
            other.evidence
        );
    }

    #[test]
    fn deduplica_alertas_repetidos_da_mesma_regra() {
        let (findings, errors) = parse_zap_findings_with_errors(DUPLICADO, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let keys: HashSet<&str> = findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect();
        assert_eq!(
            keys.len(),
            findings.len(),
            "alertas duplicados sobreviveram"
        );
    }

    #[test]
    fn json_invalido_e_reportado_em_vez_de_varrer_limpo() {
        let (findings, errors) = parse_zap_findings_with_errors(INVALIDO, TARGET);

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("JSON do ZAP inválido"), "{errors:?}");
    }

    #[test]
    fn saida_vazia_ou_diagnostica_e_reportada() {
        for output in ["", "   ", "[ERRO] Podman falhou"] {
            let (findings, errors) = parse_zap_findings_with_errors(output, TARGET);

            assert!(findings.is_empty(), "{output:?}");
            assert_eq!(errors.len(), 1, "{output:?}");
            assert!(
                errors[0].contains("não produziu relatório JSON"),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn relatorio_sem_site_nao_vira_varredura_limpa() {
        let raw = r#"{"@programName":"ZAP","@version":"2.14.0","site":[]}"#;

        let (findings, errors) = parse_zap_findings_with_errors(raw, TARGET);

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("nenhum site varrido"), "{errors:?}");
    }

    #[test]
    fn site_sem_alerta_e_reportado_como_execucao_sem_achados() {
        let raw = r#"{"site":[{"@name":"http://alvo.local","@host":"alvo.local","@port":"80","alerts":[]}]}"#;

        let (findings, errors) = parse_zap_findings_with_errors(raw, "http://alvo.local");

        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("não encontrou alertas"), "{errors:?}");
    }

    #[test]
    fn alerta_sem_referencia_e_descartado_com_erro() {
        let raw = r#"{"site":[{"@name":"http://alvo.local","alerts":[{"alert":"sem regra"}]}]}"#;

        let (findings, errors) = parse_zap_findings_with_errors(raw, "http://alvo.local");

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("sem identificador de regra"),
            "{errors:?}"
        );
    }

    #[test]
    fn alerta_sem_instancias_usa_o_alvo_e_nao_quebra() {
        let raw = r#"{"site":[{"@name":"http://alvo.local","@host":"alvo.local","@port":"80","alerts":[{"pluginid":"10038","alertRef":"10038-1","alert":"CSP ausente","riskcode":"2","confidence":"3","riskdesc":"Medium (High)"}]}]}"#;

        let (findings, errors) = parse_zap_findings_with_errors(raw, "http://alvo.local");

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].evidence.contains("url: http://alvo.local"),
            "{}",
            findings[0].evidence
        );
        assert!(
            findings[0].evidence.contains("método: não especificado"),
            "{}",
            findings[0].evidence
        );
        assert!(
            findings[0].evidence.contains("parâmetro: não informado"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn evidencia_exclui_query_string_corpos_http_e_credenciais() {
        let raw = r#"{"site":[{"@name":"http://alvo.local","@host":"alvo.local","@port":"80","alerts":[{"pluginid":"10038","alertRef":"10038-1","alert":"CSP ausente","riskcode":"2","confidence":"3","riskdesc":"Medium (High)","instances":[{"uri":"http://alvo.local/x?token=segredo&session=segredo","method":"GET","param":"authorization: Bearer segredo","evidence":"Set-Cookie: session=segredo","attack":"segredo"}]}]}]}"#;

        let (findings, _) = parse_zap_findings_with_errors(raw, "http://alvo.local");

        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert!(evidence.contains("url: http://alvo.local/x"), "{evidence}");
        assert!(!evidence.contains("token="), "{evidence}");
        assert!(!evidence.contains("session="), "{evidence}");
        assert!(!evidence.contains("segredo"), "{evidence}");
        assert!(!evidence.contains("Bearer"), "{evidence}");
        assert!(!evidence.contains("request"), "{evidence}");
        assert!(!evidence.contains("response"), "{evidence}");
    }

    #[test]
    fn limita_as_urls_preservadas_por_alerta() {
        let instances: Vec<String> = (0..10)
            .map(|index| format!(r#"{{"uri":"http://alvo.local/{index}","method":"GET"}}"#))
            .collect();
        let raw = format!(
            r#"{{"site":[{{"@name":"http://alvo.local","@host":"alvo.local","@port":"80","alerts":[{{"pluginid":"10038","alertRef":"10038-1","alert":"muitas URLs","riskcode":"2","confidence":"3","riskdesc":"Medium (High)","instances":[{}]}}]}}]}}"#,
            instances.join(",")
        );

        let (findings, errors) = parse_zap_findings_with_errors(&raw, "http://alvo.local");

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert!(evidence.contains("instances omitidas: 7"), "{evidence}");
        assert!(evidence.contains("http://alvo.local/0"), "{evidence}");
        assert!(!evidence.contains("http://alvo.local/9"), "{evidence}");
    }

    #[test]
    fn extrai_texto_de_campos_html_do_zap() {
        assert_eq!(
            html_to_text("<p>Ensure that your <b>server</b> is configured.</p>"),
            "Ensure that your server is configured."
        );
        assert_eq!(html_to_text("a &amp; b"), "a & b");
        assert_eq!(html_to_text("   "), "");
    }

    #[test]
    fn constroi_url_absoluta_para_uris_relativas() {
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
            absolute_url("http://alvo.local:3000", ""),
            "http://alvo.local:3000"
        );
    }

    #[test]
    fn a_recomendacao_traz_a_solucao_do_scanner_sem_html() {
        let (findings, _) = parse_zap_findings_with_errors(REAL, TARGET);

        let finding = &findings[0];
        assert!(
            !finding.recommendation.contains('<'),
            "{}",
            finding.recommendation
        );
        assert!(!finding.didactic.contains('<'), "{}", finding.didactic);
        assert!(finding.recommendation.contains("Content-Security-Policy"));
    }

    #[test]
    fn monta_o_endpoint_do_site_a_partir_do_host_e_porta() {
        assert_eq!(
            site_endpoint("http://alvo.local:8080", "alvo.local", "8080"),
            "alvo.local:8080"
        );
        assert_eq!(
            site_endpoint("http://alvo.local", "", ""),
            "http://alvo.local"
        );
    }
}
