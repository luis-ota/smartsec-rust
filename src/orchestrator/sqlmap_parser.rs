use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::utils::redaction::sanitize_evidence_component;
use std::collections::HashSet;

/// Cabeçalho que o SQLMap emite imediatamente antes do bloco de injeções
/// confirmadas. É o marcador que separa "achei injeção" de "não achei".
const HEADER_INJECTIONS: &str = "sqlmap identified the following injection point(s)";

/// Diagnóstico de varredura limpa: o SQLMap testou os parâmetros e nenhum
/// aceitou payload de injeção. **Não** é erro de execução.
const DIAGNOSTICO_SEM_INJECTION: &str = "do not appear to be injectable";

/// Diagnósticos de falha de execução. O SQLMap termina com status 0 em todos
/// eles, então o texto do stdout é a única evidência de que a varredura não
/// chegou a acontecer.
const DIAGNOSTICOS_DE_FALHA: &[&str] = &[
    "unable to connect to the target URL",
    "invalid target URL",
    "can't check dynamic content because of lack of page content",
];

/// Título e evidência são limitados para caber no relatório sem truncar a
/// informação essencial do achado.
const TITLE_LIMIT: usize = 120;
const EVIDENCE_LIMIT: usize = 300;

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

/// Remove a marcação `---` e o prefixo de log `[hh:mm:ss] [NÍVEL] ` das linhas
/// do SQLMap, deixando só o conteúdo da mensagem.
fn clean_line(line: &str) -> String {
    let mut value = line.trim();
    if let Some(rest) = strip_timestamp(value) {
        value = rest;
    }
    value.trim().trim_end_matches(':').trim().to_string()
}

/// Remove o prefixo `[hh:mm:ss] [LEVEL] ` das linhas do SQLMap.
///
/// A mesma mensagem aparece com `[ERROR]` ou `[CRITICAL]` dependendo de o
/// scanner estar conectado a um terminal, então o nível nunca é usado para
/// decidir o significado da linha.
fn strip_timestamp(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let (_, rest) = rest.split_once(']')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('[')?;
    let (_, rest) = rest.split_once(']')?;
    Some(rest)
}

/// Extrai o valor de uma linha no formato `Chave: valor`.
///
/// `Chave` é comparada sem diferenciar maiúsculas e o valor é o restante da
/// linha, preservado como está.
fn field_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    if trimmed.len() <= key.len() {
        return None;
    }
    let (found, rest) = trimmed.split_at(key.len());
    if !found.eq_ignore_ascii_case(key) {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let value = rest.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Separa o parâmetro e o método HTTP de `Parameter: id (GET)`.
///
/// O SQLMap escreve o método entre parênteses no fim do campo. Parâmetros sem
/// parênteses continuam válidos: o método é simplesmente desconhecido.
fn split_parameter(field: &str) -> (String, Option<String>) {
    let field = field.trim();
    match field.rfind('(') {
        Some(open) if field.ends_with(')') => {
            let name = field[..open].trim();
            let method = field[open + 1..field.len() - 1].trim();
            let name = if name.is_empty() {
                "não especificado".to_string()
            } else {
                name.to_string()
            };
            let method = if method.is_empty() {
                None
            } else {
                Some(method.to_string())
            };
            (name, method)
        }
        _ => {
            if field.is_empty() {
                ("não especificado".to_string(), None)
            } else {
                (field.to_string(), None)
            }
        }
    }
}

/// Traduz a taxonomia de tipos do próprio SQLMap para a severidade do SmartSec.
///
/// O SQLMap não emite CVSS nem severidade: a informação estruturada que ele
/// publica sobre a injeção é o campo `Type`, que é a classificação do próprio
/// scanner para a técnica confirmada. Essa taxonomia é a fonte autoritativa,
/// sem interpretar o texto da mensagem.
///
/// - `error-based` e `UNION query` exponham dados do banco diretamente na
///   resposta e sobem para ALTA.
/// - `stacked queries` executa statements arbitrários e é CRÍTICA. Não faz
///   parte do conjunto `BEUT` adotado pelo manifesto, mas a taxonomia do
///   scanner é preservada caso outra configuração o habilite.
/// - `boolean-based blind` e `time-based blind` confirmam a falha de
///   sanitização sem devolver conteúdo, e ficam em MÉDIA.
/// - Qualquer tipo novo publicado pelo scanner é MÉDIA, nunca inferior: uma
///   injeção confirmada pelo SQLMap é no mínimo esse nível.
fn severity_for(injection_type: &str) -> Severity {
    match injection_type.trim().to_ascii_lowercase().as_str() {
        "error-based" | "union query" => Severity::High,
        "stacked queries" => Severity::Critical,
        _ => Severity::Medium,
    }
}

/// Injeção confirmada no bloco do SQLMap.
struct Injection {
    parameter: String,
    method: Option<String>,
    injection_type: String,
    title: String,
}

impl Injection {
    fn dedup_key(&self) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.parameter,
            self.method.as_deref().unwrap_or_default(),
            self.injection_type,
            self.title
        )
    }
}

/// Lê o bloco de injeções confirmadas do SQLMap.
///
/// O formato foi verificado na execução real e tem duas particularidades que a
/// leitura precisa respeitar:
///
/// 1. **um `Parameter:` abre um grupo de técnicas, não um achado.** O SQLMap
///    escreve o parâmetro uma vez e lista em seguida vários conjuntos de
///    `Type:`, `Title:` e `Payload:` separados por linha em branco. Cada
///    `Type:` é um ponto de injeção distinto que herda o parâmetro corrente:
///
///    ```text
///    Parameter: id (GET)
///        Type: boolean-based blind
///        Title: AND boolean-based blind - WHERE or HAVING clause
///        Payload: ...
///
///        Type: UNION query
///        Title: Generic UNION query (NULL) - 1 column
///        Payload: ...
///    ```
///
/// 2. **um novo `Parameter:` reinicia o grupo**, separado do anterior por uma
///    linha `---`, quando mais de um parâmetro é vulnerável.
///
/// O `Payload:` é consumido e descartado: é um fragmento com forma de query
/// string, e a regra de sanitização do projeto proíbe query string em finding.
/// O `Type` e o `Title`, que são a taxonomia do próprio scanner sobre a
/// injeção, já descrevem o achado.
fn parse_injection_block(lines: &[&str]) -> (Vec<Injection>, Vec<String>) {
    let mut injections: Vec<Injection> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    // Parâmetro aberto pelo `Parameter:` corrente, herdado por cada `Type:`.
    let mut active: Option<(String, Option<String>)> = None;
    // Diz se o grupo do `Parameter:` corrente já recebeu ao menos um `Type:`.
    let mut group_has_type = false;
    // Ponto de injeção em construção, aberto pelo `Type:` corrente.
    let mut current: Option<Injection> = None;

    let start = lines
        .iter()
        .position(|line| clean_line(line).starts_with(HEADER_INJECTIONS))
        .map(|position| position + 1)
        .unwrap_or(0);

    for line in lines.iter().skip(start) {
        let content = clean_line(line);
        // Linha em branco separa pontos de injeção; o `---` abre e fecha o
        // bloco de um parâmetro.
        if content.is_empty() || content == "---" {
            continue;
        }

        if let Some(value) = field_value(&content, "Parameter") {
            // Um novo parâmetro fecha o ponto de injeção e o grupo em curso.
            if let Some(injection) = current.take() {
                injections.push(injection);
            }
            close_group(&active, group_has_type, &mut errors);
            active = Some(split_parameter(value));
            group_has_type = false;
            continue;
        }

        if let Some(value) = field_value(&content, "Type") {
            // Cada `Type:` é um ponto de injeção novo que herda o parâmetro.
            if let Some(injection) = current.take() {
                injections.push(injection);
            }
            let (parameter, method) = active
                .clone()
                .unwrap_or_else(|| ("não especificado".to_string(), None));
            group_has_type = true;
            current = Some(Injection {
                parameter,
                method,
                injection_type: value.to_string(),
                title: String::new(),
            });
            continue;
        }

        if let Some(value) = field_value(&content, "Title") {
            if let Some(injection) = current.as_mut() {
                injection.title = value.to_string();
            }
            continue;
        }
        // O `Payload:` é lido e descartado de propósito.
    }

    if let Some(injection) = current.take() {
        injections.push(injection);
    }
    close_group(&active, group_has_type, &mut errors);
    (injections, errors)
}

/// Fecha o grupo do `Parameter:` corrente e registra o erro quando o grupo
/// não recebeu nenhum `Type:`.
///
/// Um grupo sem tipo é um bloco truncado ou de formato diferente: não pode
/// virar achado (não há classificação da injeção) nem varredura limpa.
fn close_group(
    active: &Option<(String, Option<String>)>,
    group_has_type: bool,
    errors: &mut Vec<String>,
) {
    if group_has_type {
        return;
    }
    let Some((parameter, _)) = active else {
        return;
    };
    errors.push(format!(
        "o SQLMap reportou a injeção no parâmetro '{parameter}' sem informar o tipo; o achado foi descartado"
    ));
}

/// Sufixos que o SQLMap acrescenta ao diagnóstico e que não descrevem a falha.
///
/// A linha de erro do SQLMap vem precedida de uma `[CRITICAL]` de retry com o
/// texto "sqlmap is going to retry the request(s)". Essa frase contém a
/// palavra `request`, que `utils::redaction` trata como chave de corpo HTTP e
/// portanto redigiria a mensagem inteira, escondendo do operador o diagnóstico
/// real. Usar a **última** linha que casa com o marcador e remover os sufixos
/// conhecidos deixa a mensagem essencial, que sobrevive à sanitização.
const SUFFIXOS_DE_DIAGNOSTICO: &[&str] = &[
    ", skipping to the next target",
    ". sqlmap is going to retry the request(s)",
];

/// Procura, no stdout, um diagnóstico de falha de execução.
///
/// O SQLMap sempre termina com status 0, mesmo quando não alcança o alvo, e
/// escreve o diagnóstico no stdout — o `stderr` fica vazio. Sem esta busca a
/// varredura seria reportada como limpa.
fn failure_message(output: &str) -> Option<String> {
    DIAGNOSTICOS_DE_FALHA.iter().find_map(|marker| {
        let line = output
            .lines()
            .map(clean_line)
            .rfind(|line| line.contains(marker))?;
        let mut line = line.as_str();
        for suffix in SUFFIXOS_DE_DIAGNOSTICO {
            if let Some(remaining) = line.strip_suffix(suffix) {
                line = remaining;
            }
        }
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let sanitized = sanitize_evidence_component(line);
        if sanitized.is_empty() || sanitized == "[REDACTED]" {
            // A sanitização removeu a mensagem inteira; ainda assim o operador
            // precisa saber que o SQLMap não executou a varredura.
            return Some(format!(
                "o SQLMap não conseguiu executar a varredura e o diagnóstico do scanner foi omitido pela sanitização ({marker})"
            ));
        }
        Some(format!(
            "o SQLMap não conseguiu executar a varredura: {sanitized}"
        ))
    })
}

/// Parseia a saída do SQLMap e retorna achados reais com proveniência completa.
///
/// Parâmetro, método HTTP, tipo e título da injeção são preservados: o `Type` e
/// o `Title` são a taxonomia do próprio scanner sobre a injeção confirmada. A
/// evidência nunca inclui o `Payload`, que é um fragmento com forma de query
/// string.
///
/// Diagnósticos de varredura limpa (nenhum parâmetro injetável) não viram
/// vulnerabilidade nem erro. Já uma saída que o SQLMap não conseguiu produzir,
/// um alvo inalcançável e um alvo inválido viram erro de execução: saída não
/// reconhecida nunca é tratada como varredura limpa.
#[allow(dead_code)]
pub fn parse_sqlmap_findings(output: &str, target: &str) -> Vec<Vulnerability> {
    parse_sqlmap_findings_with_errors(output, target).0
}

/// Retorna os achados e os erros da execução. Saída inválida nunca é tratada
/// como varredura limpa e silenciosa.
pub fn parse_sqlmap_findings_with_errors(
    output: &str,
    target: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.starts_with("[ERRO]") {
        return (
            Vec::new(),
            vec![
                "o SQLMap não produziu um resultado analisável; a execução precisa ser revisada"
                    .to_string(),
            ],
        );
    }

    if let Some(message) = failure_message(trimmed) {
        return (Vec::new(), vec![message]);
    }

    let lines: Vec<&str> = trimmed.lines().collect();
    let reports_injections = lines
        .iter()
        .any(|line| clean_line(line).contains(HEADER_INJECTIONS));
    let reports_clean_scan = lines
        .iter()
        .any(|line| clean_line(line).contains(DIAGNOSTICO_SEM_INJECTION));

    if !reports_injections && !reports_clean_scan {
        // Nem o cabeçalho de injeção nem o diagnóstico de varredura limpa: o
        // texto não é um resultado do SQLMap reconhecível, e isso não pode
        // virar "varredura limpa".
        return (
            Vec::new(),
            vec![
                "a saída do SQLMap não contém o resultado esperado; a execução precisa ser revisada"
                    .to_string(),
            ],
        );
    }

    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let detected_at = now_iso8601();

    let (injections, block_errors) = parse_injection_block(&lines);
    errors.extend(block_errors);

    for injection in injections {
        if injection.injection_type.trim().is_empty() {
            errors.push(format!(
                "o SQLMap reportou a injeção no parâmetro '{}' sem informar o tipo; o achado foi descartado",
                injection.parameter
            ));
            continue;
        }
        if !seen.insert(injection.dedup_key()) {
            continue;
        }

        let severity = severity_for(&injection.injection_type);
        let method_label = injection.method.as_deref().unwrap_or("não especificado");
        let detail = if injection.title.trim().is_empty() {
            format!(
                "tipo {} (o SQLMap não descreveu a técnica)",
                injection.injection_type
            )
        } else {
            truncate(injection.title.trim(), EVIDENCE_LIMIT)
        };

        let title = format!(
            "Injeção SQL confirmada em {} ({}) — {}",
            injection.parameter, method_label, detail
        );
        let description = format!(
            "O SQLMap confirmou injeção de SQL no parâmetro {method_label} '{parameter}' do alvo, pela técnica '{injection_type}' ({detail}). A falha permite que a entrada do usuário altere a consulta enviada ao banco de dados.",
            parameter = injection.parameter,
            injection_type = injection.injection_type,
        );
        let recommendation = format!(
            "Use consultas parametrizadas (prepared statements) no parâmetro {} e dispense a concatenação de entrada do usuário na cláusula WHERE. Depois da correção, repita a varredura para confirmar que a injeção deixou de ser reproduzida.",
            injection.parameter
        );
        let didactic = format!(
            "O SQLMap alterou a consulta do banco de dados a partir do parâmetro '{parameter}' e conseguiu observar a diferença na resposta ({injection_type}).\n\nSeveridade atribuída a partir da taxonomia de tipos do próprio scanner: {}\n\nIsso significa que a entrada do usuário está sendo interpretada como SQL. O impacto depende de quais operações o banco aceita, e por isso a confirmação precisa ser feita no ambiente autorizado antes de tratar como vulnerabilidade corrigível.",
            severity.label_pt_br(),
            parameter = injection.parameter,
            injection_type = injection.injection_type,
        );

        let safe_parameter = sanitize_evidence_component(&injection.parameter);
        let safe_method = sanitize_evidence_component(method_label);
        let safe_type = sanitize_evidence_component(&injection.injection_type);
        let safe_detail = sanitize_evidence_component(&detail);
        let safe_url = sanitize_evidence_component(target);

        findings.push(Vulnerability {
            title: truncate(&title, TITLE_LIMIT),
            severity,
            description,
            tool: "SQLMap".to_string(),
            recommendation,
            didactic,
            source: FindingSource::Real,
            target: target.to_string(),
            evidence: format!(
                "sqlmap parâmetro: {safe_parameter} | método: {safe_method} | tipo: {safe_type} | técnica: {safe_detail} | url: {safe_url}"
            ),
            detected_at: detected_at.clone(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            code_location: None,
            code_remediation: Vec::new(),
        });
    }

    (findings, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::sqlmap::container_arguments;

    const CONFIRMADA: &str = include_str!("../../tests/fixtures/sqlmap/injection_confirmada.txt");
    const SEM_INJECTION: &str = include_str!("../../tests/fixtures/sqlmap/sem_injection.txt");
    const ALVO_INVALIDO: &str = include_str!("../../tests/fixtures/sqlmap/alvo_invalido.txt");
    const INALCANCAVEL: &str = include_str!("../../tests/fixtures/sqlmap/alvo_inalcancavel.txt");
    const INVALIDO: &str = include_str!("../../tests/fixtures/sqlmap/invalido.txt");
    const DUPLICADO: &str = include_str!("../../tests/fixtures/sqlmap/duplicado.txt");

    const TARGET: &str = "http://169.254.1.2:3100/item?id=1";

    #[test]
    fn preserva_parametro_tipo_e_tecnica_da_injecao_confirmada() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(CONFIRMADA, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 3);

        let boolean = &findings[0];
        assert_eq!(boolean.tool, "SQLMap");
        assert_eq!(boolean.source, FindingSource::Real);
        assert_eq!(boolean.target, TARGET);

        // Parâmetro e método preservados.
        assert!(
            boolean.evidence.contains("parâmetro: id"),
            "{}",
            boolean.evidence
        );
        assert!(
            boolean.evidence.contains("método: GET"),
            "{}",
            boolean.evidence
        );
        // Tipo de injeção preservado.
        assert!(
            boolean.evidence.contains("tipo: boolean-based blind"),
            "{}",
            boolean.evidence
        );
        // Título da técnica, da taxonomia do próprio scanner.
        assert!(
            boolean
                .evidence
                .contains("técnica: AND boolean-based blind - WHERE or HAVING clause"),
            "{}",
            boolean.evidence
        );
        // A URL entra sanitizada, sem a query string do alvo.
        assert!(
            boolean
                .evidence
                .contains("url: http://169.254.1.2:3100/item"),
            "{}",
            boolean.evidence
        );
        assert!(!boolean.evidence.contains("?id="), "{}", boolean.evidence);
    }

    #[test]
    fn preserva_cada_tipo_de_injecao_do_bloco() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(CONFIRMADA, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        for expected in ["boolean-based blind", "time-based blind", "UNION query"] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.evidence.contains(&format!("tipo: {expected}"))),
                "tipo ausente: {expected}\n{findings:#?}"
            );
        }
    }

    #[test]
    fn a_evidencia_nunca_inclui_o_payload_de_injecao() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(CONFIRMADA, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        for finding in &findings {
            // O `Payload:` é um fragmento com forma de query string e por isso
            // não pode aparecer em finding.
            assert!(
                !finding.evidence.contains("Payload"),
                "{}",
                finding.evidence
            );
            assert!(
                !finding.evidence.contains("RANDOMBLOB"),
                "{}",
                finding.evidence
            );
            assert!(
                !finding.evidence.contains("UNION ALL SELECT"),
                "{}",
                finding.evidence
            );
            assert!(
                !finding.evidence.contains("AND 1612=1612"),
                "{}",
                finding.evidence
            );
            assert!(
                !finding.description.contains("UNION ALL SELECT"),
                "{}",
                finding.description
            );
        }
    }

    #[test]
    fn a_severidade_vem_da_taxonomia_de_tipos_do_scanner() {
        assert_eq!(severity_for("boolean-based blind"), Severity::Medium);
        assert_eq!(severity_for("time-based blind"), Severity::Medium);
        assert_eq!(severity_for("error-based"), Severity::High);
        assert_eq!(severity_for("UNION query"), Severity::High);
        // Técnica destrutiva, fora do conjunto BEUT adotado no manifesto.
        assert_eq!(severity_for("stacked queries"), Severity::Critical);
        // Tipo novo do scanner nunca pode gerar severidade inferior.
        assert_eq!(severity_for("tecnica-nova-2027"), Severity::Medium);
    }

    #[test]
    fn separacao_do_parametro_e_do_metodo() {
        assert_eq!(
            split_parameter("id (GET)"),
            ("id".to_string(), Some("GET".to_string()))
        );
        assert_eq!(
            split_parameter("usuario (POST)"),
            ("usuario".to_string(), Some("POST".to_string()))
        );
        // Parâmetro sem método informado pelo scanner.
        assert_eq!(split_parameter("id"), ("id".to_string(), None));
        assert_eq!(split_parameter(""), ("não especificado".to_string(), None));
    }

    #[test]
    fn varredura_sem_injecao_e_limpa_e_nao_e_erro() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(SEM_INJECTION, TARGET);

        assert!(findings.is_empty(), "{findings:#?}");
        assert!(
            errors.is_empty(),
            "não encontrar injeção é resultado legítimo, não erro.\n{errors:?}"
        );
    }

    #[test]
    fn alvo_inalcancavel_vira_erro_e_nao_varredura_limpa() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(INALCANCAVEL, TARGET);

        assert!(findings.is_empty(), "{findings:#?}");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("não conseguiu executar a varredura"),
            "{errors:?}"
        );
        assert!(
            errors[0].contains("unable to connect to the target URL"),
            "{errors:?}"
        );
    }

    #[test]
    fn alvo_invalido_vira_erro_e_nao_varredura_limpa() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(ALVO_INVALIDO, TARGET);

        assert!(findings.is_empty(), "{findings:#?}");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("invalid target URL"), "{errors:?}");
    }

    #[test]
    fn saida_nao_reconhecida_e_reportada_em_vez_de_varrer_limpo() {
        for output in [
            INVALIDO,
            "SQLMap comecou e foi interrompido no meio da varredura.\n",
            "[ERRO] O container abc excedeu o tempo limite de 15 minutos.",
        ] {
            let (findings, errors) = parse_sqlmap_findings_with_errors(output, TARGET);

            assert!(findings.is_empty(), "{output:?}");
            assert_eq!(errors.len(), 1, "{output:?} -> {errors:?}");
            assert!(
                !errors[0].is_empty(),
                "saída inválida precisa virar erro.\n{output:?}"
            );
        }
    }

    #[test]
    fn saida_vazia_e_diagnostica_e_reportada() {
        for output in ["", "   ", "\n\n"] {
            let (findings, errors) = parse_sqlmap_findings_with_errors(output, TARGET);

            assert!(findings.is_empty(), "{output:?}");
            assert_eq!(errors.len(), 1, "{output:?}");
            assert!(
                errors[0].contains("não produziu um resultado analisável"),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn deduplica_pontos_de_injecao_repetidos() {
        let (findings, errors) = parse_sqlmap_findings_with_errors(DUPLICADO, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        // O fixture repete boolean-based e time-based; sobrevivem 2 achados.
        assert_eq!(findings.len(), 2, "{findings:#?}");
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
    fn injecao_sem_tipo_e_descartada_com_erro() {
        let raw = "sqlmap identified the following injection point(s) with a total of 7 HTTP(s) requests:\n---\nParameter: id (GET)\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\n---\n";

        let (findings, errors) = parse_sqlmap_findings_with_errors(raw, TARGET);

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("sem informar o tipo"), "{errors:?}");
    }

    #[test]
    fn a_mensagem_de_diagnostico_preserva_o_nivel_em_qualquer_caixa() {
        // A mesma mensagem do SQLMap aparece como [ERROR] ou [CRITICAL]
        // dependendo do modo de execução; o parser casa pelo texto.
        let as_error = "[19:17:14] [ERROR] all tested parameters do not appear to be injectable. skipping to the next target";
        let as_critical =
            "[19:17:14] [CRITICAL] all tested parameters do not appear to be injectable. skipping to the next target";

        for output in [as_error, as_critical] {
            let (findings, errors) = parse_sqlmap_findings_with_errors(output, TARGET);
            assert!(findings.is_empty(), "{output}");
            assert!(errors.is_empty(), "{output} -> {errors:?}");
        }
    }

    #[test]
    fn evidencia_exclui_corpos_http_credenciais_e_query_string() {
        let raw = "sqlmap identified the following injection point(s) with a total of 9 HTTP(s) requests:\n---\nParameter: session (COOKIE)\n    Type: error-based\n    Title: Cookie: session=segredo; Authorization: Bearer segredo\n    Payload: session=segredo\n---\n";

        let (findings, errors) = parse_sqlmap_findings_with_errors(raw, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert!(evidence.contains("parâmetro: session"), "{evidence}");
        assert!(evidence.contains("tipo: error-based"), "{evidence}");
        assert!(!evidence.contains("segredo"), "{evidence}");
        assert!(
            !evidence.to_lowercase().contains("authorization"),
            "{evidence}"
        );
        assert!(!evidence.contains("Cookie:"), "{evidence}");
        assert!(!evidence.contains("request"), "{evidence}");
        assert!(!evidence.contains("response"), "{evidence}");
    }

    #[test]
    fn metodo_ausente_nao_quebra_o_achado() {
        let raw = "sqlmap identified the following injection point(s):\n---\nParameter: id\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n---\n";

        let (findings, errors) = parse_sqlmap_findings_with_errors(raw, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].evidence.contains("método: não especificado"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn mensagens_longas_sao_truncadas() {
        let raw = format!(
            "sqlmap identified the following injection point(s):\n---\nParameter: id (GET)\n    Type: boolean-based blind\n    Title: {}\n---\n",
            "x".repeat(1000)
        );

        let (findings, errors) = parse_sqlmap_findings_with_errors(&raw, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.chars().count() < 700);
        assert!(findings[0].title.chars().count() <= TITLE_LIMIT + 1);
    }

    #[test]
    fn o_manifesto_usa_o_comando_validado_no_container() {
        let arguments = container_arguments(TARGET);

        // Não interativo é obrigatório: sem `--batch` o SQLMap trava e sem
        // `--answers` ele responde Y à pergunta de exploração do banco.
        assert!(arguments.iter().any(|argument| argument == "--batch"));
        assert!(arguments.windows(2).any(|pair| pair
            == [
                "--answers",
                "exploit=N,keep testing=N,reduce the number of requests=Y,proceed=C"
            ]));
        // Técnicas destrutivas fora do conjunto.
        assert!(arguments
            .iter()
            .any(|argument| argument == "--technique=BEUT"));
        // Saída em arquivo, não no stdout do parser.
        assert!(arguments
            .iter()
            .any(|argument| argument == "--output-dir=/tmp"));
        assert!(arguments.iter().any(|argument| argument == TARGET));
    }
}
