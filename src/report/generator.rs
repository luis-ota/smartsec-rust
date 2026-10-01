use crate::config::Configuration;
use crate::domain::security_tool::SecurityTool;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::DecisionRecord;
use crate::orchestrator::enrichment::EnrichmentSummary;
use crate::orchestrator::nvd::cache_dir;

pub struct ReportGenerator;

impl ReportGenerator {
    /// Relatório sem contexto de enriquecimento.
    ///
    /// Mantido para os testes e para consumidores que ainda não enrichecem os
    /// achados; delega para [`compile_report_with_enrichment`](Self::compile_report_with_enrichment).
    #[allow(dead_code)]
    pub fn compile_report(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
        project_dir: Option<&std::path::Path>,
        ai_analysis: &str,
        failed_executions: &[SecurityTool],
    ) -> String {
        Self::compile_report_with_enrichment(
            config,
            vulns,
            decisions,
            &EnrichmentSummary::default(),
            project_dir,
            ai_analysis,
            failed_executions,
        )
    }

    /// Monta o relatório incluindo a correlação e o enriquecimento CVE/NVD.
    ///
    /// A indisponibilidade da NVD **não** impede este relatório: ela aparece
    /// como seção com a causa, e o restante do documento sai normalmente.
    pub fn compile_report_with_enrichment(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
        enrichment: &EnrichmentSummary,
        project_dir: Option<&std::path::Path>,
        ai_analysis: &str,
        failed_executions: &[SecurityTool],
    ) -> String {
        let vulns = vulns
            .iter()
            .map(Vulnerability::sanitized)
            .collect::<Vec<_>>();
        let mut md = String::new();
        md.push_str("# SmartSec - Relatório de Análise de Segurança\n\n");
        md.push_str(&format!(
            "**URL Alvo:** {}\n\n",
            crate::utils::redaction::sanitize_url(&config.target_url)
        ));
        md.push_str(&format!("**Modo:** {}\n\n", config.execution_type));
        md.push_str("**Dados:** REAL\n\n");
        append_enrichment_section(&mut md, enrichment);
        // O diretório do projeto entra no cabeçalho mesmo quando nenhum achado
        // foi localizado: ele declara **qual árvore foi analisada**, e um
        // relatório que não diz isso deixa a auditoria sem forma de saber se a
        // fase de código rodou sobre o repositório certo.
        if let Some(project_dir) = project_dir {
            md.push_str(&format!(
                "**Projeto analisado:** {}\n\n",
                crate::utils::redaction::sanitize_text(&project_dir.display().to_string())
            ));
        }
        if !decisions.is_empty() {
            md.push_str("## Decisões Dinâmicas\n\n");
            for decision in decisions {
                let decision = decision.sanitized();
                md.push_str(&format!("### {}\n\n", escape_markdown(&decision.summary())));
                md.push_str(&format!("- Modelo: {}\n", escape_markdown(&decision.model)));
                md.push_str(&format!(
                    "- Justificativa: {}\n",
                    escape_markdown(&decision.justification)
                ));
                md.push_str(&format!("- Parâmetros: {:?}\n", decision.parameters));
                md.push_str(&format!("- Evidências: {:?}\n\n", decision.evidence));
            }
        }
        if !ai_analysis.trim().is_empty() {
            md.push_str("## Análise da IA\n\n");
            // A análise da IA passa pela mesma sanitização dos demais campos
            // dinâmicos antes de ser escapada para Markdown. É o único trecho
            // do relatório produzido por um modelo, e um modelo pode
            // parafrasear o valor de um segredo detectado em vez de copiá-lo —
            // o que a sanitização por palavra-chave do scanner não alcança
            // depois que o texto passou por ele.
            let sanitized_analysis = crate::utils::redaction::sanitize_text(ai_analysis);
            md.push_str(&escape_markdown_block(&sanitized_analysis));
            md.push_str("\n\n");
        }
        md.push_str("## Resumo\n\n");
        md.push_str(&format!("- Total de vulnerabilidades: {}\n", vulns.len()));
        let crit = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Critical)
            .count();
        let high = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::High)
            .count();
        let med = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Medium)
            .count();
        let low = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Low)
            .count();
        let info = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Info)
            .count();
        md.push_str(&format!(
            "- Críticas: {}\n- Altas: {}\n- Médias: {}\n- Baixas: {}\n- Informativas: {}\n\n",
            crit, high, med, low, info
        ));
        md.push_str("## Pontos Críticos\n\n");
        for v in &vulns {
            if v.severity == crate::domain::Severity::Critical
                || v.severity == crate::domain::Severity::High
            {
                md.push_str(&format!(
                    "### [{}] {}\n\n",
                    v.severity.label_pt_br(),
                    escape_markdown(&v.title)
                ));
                md.push_str(&format!("{}\n\n", escape_markdown_block(&v.description)));
                md.push_str(&format!("**Ferramenta:** {}\n\n", escape_markdown(&v.tool)));
                append_code_analysis(&mut md, v);
                append_provenance(&mut md, v);
                md.push_str(&format!(
                    "**Recomendação:** {}\n\n",
                    escape_markdown(&v.recommendation)
                ));
                if !v.didactic.trim().is_empty() {
                    md.push_str(&format!(
                        "**Em linguagem simples:** {}\n\n",
                        escape_markdown(&v.didactic)
                    ));
                }
            }
        }
        md.push_str("## Todas as Vulnerabilidades\n\n");
        for v in &vulns {
            md.push_str(&format!(
                "- [{}] {} - {} - código: {}\n",
                v.severity.label_pt_br(),
                escape_markdown(&v.title),
                escape_markdown(&v.tool),
                code_location_label(v)
            ));
        }
        append_code_analysis_section(&mut md, &vulns);
        if !failed_executions.is_empty() {
            // Filtra de novo em vez de confiar no chamador: um histórico completo
            // passado por engano não pode listar execuções bem-sucedidas como
            // falha e contaminar a leitura do relatório.
            let com_erro: Vec<&SecurityTool> = failed_executions
                .iter()
                .filter(|execution| execution.execution_error.is_some())
                .collect();
            if !com_erro.is_empty() {
                md.push_str("\n## Execuções com falha\n\n");
                md.push_str(
                    "As execuções abaixo falharam ou foram interrompidas. Nenhum achado foi \
                     produzido por elas.\n\n",
                );
                for execution in com_erro {
                    md.push_str(&format!(
                        "- Ferramenta: {} | Status: {} | Duração: {} ms\n",
                        escape_markdown(&execution.tool_name),
                        escape_markdown(&execution.status),
                        execution.duration_ms
                    ));
                    md.push_str(&format!(
                        "  - Erro: {}\n",
                        escape_markdown(
                            execution
                                .execution_error
                                .as_deref()
                                .unwrap_or("não informado")
                        )
                    ));
                }
            }
        }
        md.push_str("\n## Proveniência dos achados\n\n");
        for vulnerability in &vulns {
            append_provenance(&mut md, vulnerability);
        }
        md
    }

    pub fn export_to_markdown(content: &str, path: &str) -> anyhow::Result<()> {
        write_report_file(path, content.as_bytes())
    }

    pub fn export_to_pdf(content: &str, path: &str) -> anyhow::Result<()> {
        let bytes = crate::report::pdf::render(content)?;
        write_report_file(path, &bytes)
    }
}

/// Rótulo da origem no código, ou o texto honesto de "não determinada".
fn code_location_label(vulnerability: &Vulnerability) -> String {
    vulnerability.code_location.as_ref().map_or_else(
        || crate::code_agent::agent::UNDETERMINED_LABEL.to_string(),
        ToString::to_string,
    )
}

/// Escreve a localização e os passos de correção de um achado.
///
/// A severidade não aparece aqui de propósito: o agente de código aponta onde
/// corrigir e nunca reclassifica (TCC_SPEC, seção 7).
fn append_code_analysis(md: &mut String, vulnerability: &Vulnerability) {
    let Some(location) = vulnerability.code_location.as_ref() else {
        return;
    };
    md.push_str(&format!(
        "**Origem no código:** {}:{}\n\n",
        location.file, location.line
    ));
    if !vulnerability.code_remediation.is_empty() {
        md.push_str("**Correção sugerida no código:**\n\n");
        for step in &vulnerability.code_remediation {
            md.push_str(&format!("- {step}\n"));
        }
        md.push('\n');
    }
}

/// Seção dedicada à análise do código.
///
/// A seção lista **todos** os achados, inclusive os sem origem, com o motivo da
/// recusa quando houver. Omitir os não localizados faria o relatório parecer
/// mais preciso do que foi: o número de achados sem origem é informação de
/// auditoria, não ruído.
fn append_code_analysis_section(md: &mut String, vulns: &[Vulnerability]) {
    let located = vulns.iter().filter(|v| v.code_location.is_some()).count();
    md.push_str("\n## Localização no código\n\n");
    md.push_str(&format!(
        "- Achados com origem localizada: {located} de {}\n\n",
        vulns.len()
    ));
    for vulnerability in vulns {
        md.push_str(&format!(
            "### [{}] {}\n\n",
            vulnerability.severity.label_pt_br(),
            escape_markdown(&vulnerability.title)
        ));
        match vulnerability.code_location.as_ref() {
            Some(location) => {
                md.push_str(&format!(
                    "**Arquivo:** `{}` · **Linha:** {}\n\n",
                    escape_markdown(&location.file),
                    location.line
                ));
                if !location.snippet.is_empty() {
                    md.push_str(&format!("```\n{}\n```\n\n", location.snippet));
                }
            }
            None => md.push_str(&format!(
                "**Arquivo:** {} · **Linha:** —\n\n",
                crate::code_agent::agent::UNDETERMINED_LABEL
            )),
        }
        if vulnerability.code_remediation.is_empty() {
            md.push_str("**Correção sugerida:** não determinada.\n\n");
        } else {
            md.push_str("**Correção sugerida:**\n\n");
            for step in &vulnerability.code_remediation {
                md.push_str(&format!("- {}\n", escape_markdown_block(step)));
            }
            md.push('\n');
        }
    }
}

/// Grava um artefato do relatório criando o diretório de destino quando falta.
///
/// O erro carrega o caminho e a causa do sistema para que a falha chegue ao
/// operador em vez de virar um sucesso silencioso (critério de aceite 2).
fn write_report_file(path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;

    let path = std::path::Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "não foi possível criar o diretório '{}' para o relatório",
                parent.display()
            )
        })?;
    }
    std::fs::write(path, bytes).with_context(|| {
        format!(
            "não foi possível gravar o relatório em '{}'",
            path.display()
        )
    })
}

/// Caracteres whose *inline* syntax is escapable by backslash in CommonMark.
///
/// `<` and `>` are escapable too, which is what stops text coming from a scanner
/// from being read as HTML. The list is deliberately narrow: `.`, `:`, `/`, `!`,
/// `(`, `)`, `{`, `}` and `$` are left alone because they carry no inline
/// meaning once `[`, `]`, `<` and `>` are escaped, and escaping them would
/// corrupt legitimate report text such as `nginx/1.24.0 (Ubuntu)`, `3.14` and
/// `http://alvo.local/api/v1`.
const MARKDOWN_ESCAPABLE: &[char] = &['\\', '`', '*', '_', '[', ']', '<', '>', '|', '~'];

/// Characters that only mean something at the *start of a line*: headings,
/// bullet and ordered lists, block quotes and setext underlines.
///
/// These are escaped only when they lead a line, so `pt-BR`, `--` and `+55 11`
/// inside a sentence stay readable while a description line cannot promote
/// itself to a heading.
const MARKDOWN_LINE_PREFIX: &[char] = &['#', '-', '+', '>', '='];

/// Marcador emitido por `sanitize_text` quando uma linha inteira é removida.
///
/// Ele é produzido pelo SmartSec, não pelo scanner, então não é conteúdo
/// dinâmico e não pode ser escapado: escapado viraria `\[REDACTED\]` no
/// Markdown e o contrato de redação documentado nos testes deixaria de valer.
const REDACTION_MARKER: &str = "[REDACTED]";

/// O mesmo marcador depois de passar por [`escape_markdown`], que colocaria uma
/// barra invertida antes de cada colchete.
const ESCAPED_REDACTION_MARKER: &str = "\\[REDACTED\\]";

/// Escapa texto dinâmico destinado a uma única linha de Markdown.
///
/// Quebras de linha e caracteres de controle viram espaço: um título vindo de um
/// scanner não pode injetar um novo bloco (`##`) nem deslocar a linha seguinte.
pub fn escape_markdown(text: &str) -> String {
    escape_with(text, false)
}

/// Escapa texto dinâmico destinado a vários parágrafos, preservando as quebras.
///
/// Cada linha é escapada por [`escape_markdown`], então um parágrafo de análise
/// continua legível sem que uma linha do meio vire título ou lista.
pub fn escape_markdown_block(text: &str) -> String {
    escape_with(text, true)
}

/// Implementação comum dos dois escapes.
///
/// `block` habilita o escape de caractere inicial de linha e preserva a quebra
/// de linha; no modo de linha única a quebra vira espaço, porque um título não
/// pode abrir um bloco novo nem deslocar o conteúdo seguinte.
fn escape_with(text: &str, block: bool) -> String {
    let mut escaped = String::with_capacity(text.len());
    let mut line_start = true;
    for character in text.chars() {
        if character == '\n' {
            if block {
                escaped.push('\n');
            } else {
                escaped.push(' ');
            }
            line_start = true;
        } else if character == '\r' {
            if !block {
                escaped.push(' ');
            }
        } else if character.is_control() {
            escaped.push(' ');
            line_start = false;
        } else if MARKDOWN_ESCAPABLE.contains(&character)
            || (block && line_start && MARKDOWN_LINE_PREFIX.contains(&character))
        {
            escaped.push('\\');
            escaped.push(character);
            line_start = false;
        } else {
            escaped.push(character);
            line_start = false;
        }
    }
    escaped.replace(ESCAPED_REDACTION_MARKER, REDACTION_MARKER)
}

/// Remove o escape de [`escape_markdown`], devolvendo o texto como o leitor vê.
///
/// O renderizador de PDF usa isto para exibir o caractere real (`*`) e não a
/// sequência escapada (`\*`), que é o que um leitor de Markdown faz.
pub fn unescape_markdown(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            if let Some(next) = characters.next() {
                if MARKDOWN_ESCAPABLE.contains(&next) {
                    plain.push(next);
                } else {
                    plain.push('\\');
                    plain.push(next);
                }
            } else {
                plain.push('\\');
            }
        } else {
            plain.push(character);
        }
    }
    plain
}

fn append_provenance(md: &mut String, vulnerability: &Vulnerability) {
    md.push_str(&format!(
        "**Origem:** {}\n\n**Alvo:** {}\n\n**Evidência:** {}\n\n**Timestamp:** {}\n\n",
        escape_markdown(&vulnerability.source.to_string()),
        escape_markdown(&vulnerability.target),
        escape_markdown(&vulnerability.evidence),
        escape_markdown(&vulnerability.detected_at)
    ));
    // Toda origem do mesmo problema é listada: o merge agrega e não descarta.
    for origin in &vulnerability.origins {
        md.push_str(&format!(
            "- Origem correlacionada — ferramenta: {} · severidade: {} · evidência: {} · detectada em: {}\n",
            origin.tool,
            origin.severity.label_pt_br(),
            origin.evidence,
            origin.detected_at
        ));
    }
    if !vulnerability.origins.is_empty() {
        md.push('\n');
    }
    if let Some(enrichment) = vulnerability.enrichment.as_ref() {
        md.push_str(&format!(
            "**Contexto NVD:** {}, CVSS base {}, severidade NVD {}, versão CVSS {}, referência {}, consultado em {}{}\n\n",
            enrichment.cve_id,
            enrichment
                .cvss_base_score
                .map_or_else(|| "não pontuado".to_string(), |score| format!("{score:.1}")),
            enrichment
                .cvss_severity
                .map_or("NÃO INFORMADA", |severity| severity.label_pt_br()),
            enrichment.cvss_version.as_deref().unwrap_or("não informada"),
            enrichment.reference.as_deref().unwrap_or("não informada"),
            enrichment.queried_at,
            if enrichment.from_cache {
                " (cache local)"
            } else {
                ""
            }
        ));
        if let Some(vector) = enrichment.cvss_vector.as_deref() {
            md.push_str(&format!("**Vetor CVSS:** {vector}\n\n"));
        }
    }
    if let Some(conflict) = vulnerability.severity_conflict.as_ref() {
        md.push_str(&format!(
            "**Divergência de severidade:** {}\n\n",
            conflict.detail
        ));
    }
}

/// Seção de correlação e enriquecimento CVE/NVD.
///
/// Quando a NVD está indisponível, a causa é impressa: o relatório base sai
/// igual e o leitor sabe por que o contexto não foi obtido.
fn append_enrichment_section(md: &mut String, enrichment: &EnrichmentSummary) {
    if enrichment.correlation.input_count == 0 && !enrichment.is_degraded() {
        return;
    }
    md.push_str("## Correlação e enriquecimento CVE/NVD\n\n");
    md.push_str(&format!(
        "- {}\n- {}\n",
        enrichment.correlation.summary_pt_br(),
        enrichment.nvd.summary_pt_br()
    ));
    md.push_str(&format!(
        "- Cache local da NVD: `{}` com validade de {} dias.\n",
        cache_dir().display(),
        crate::orchestrator::nvd::cache_ttl_days()
    ));
    md.push_str(&format!(
        "- Limite de taxa respeitado: {}.\n",
        crate::orchestrator::nvd::rate_limit_pt_br()
    ));
    if enrichment.nvd.is_degraded() {
        md.push_str(
            "- **Nota:** a indisponibilidade da NVD não altera a severidade de nenhum achado e não impede a emissão deste relatório.\n",
        );
    }
    md.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    /// O relatório precisa declarar qual árvore de código foi analisada, mesmo
    /// quando nenhum achado foi localizado. Sem isso, um relatório com a seção
    /// "Localização no código" vazia seria indistinguível de uma fase que rodou e
    /// não encontrou origem.
    #[test]
    fn the_report_declares_the_analyzed_project() {
        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            Some(std::path::Path::new("/home/operador/projeto")),
            "",
            &[],
        );

        assert!(
            report.contains("**Projeto analisado:** /home/operador/projeto"),
            "{report}"
        );
    }

    /// A localização e a correção no código entram no relatório, e um achado
    /// sem origem aparece explicitamente como "não determinada".
    #[test]
    fn the_report_shows_the_location_and_the_remediation_per_finding() {
        let located = Vulnerability {
            title: "Autenticação fraca".to_string(),
            severity: Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            code_location: Some(crate::domain::vulnerability::CodeLocation {
                file: "src/app.py".to_string(),
                line: 4,
                snippet: "raise ValueError".to_string(),
            }),
            code_remediation: vec!["Valide o usuário antes de prosseguir".to_string()],
            ..Default::default()
        };
        let without = Vulnerability {
            title: "Cabeçalho ausente".to_string(),
            severity: Severity::Info,
            description: "Descrição".to_string(),
            tool: "Nikto".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            ..Default::default()
        };

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[located, without],
            &[],
            Some(std::path::Path::new("/tmp/projeto")),
            "",
            &[],
        );

        assert!(report.contains("src/app.py"), "{report}");
        assert!(report.contains("**Linha:** 4"), "{report}");
        assert!(
            report.contains("Valide o usuário antes de prosseguir"),
            "{report}"
        );
        assert!(
            report.contains("Achados com origem localizada: 1 de 2"),
            "o relatório precisa dizer quantos achados ficaram sem origem: {report}"
        );
        assert!(
            report.contains("localização não determinada"),
            "um achado sem origem não pode sumir do relatório: {report}"
        );
    }

    /// A severidade do scanner é autoritativa (TCC_SPEC, seção 7): o agente
    /// de código aponta onde corrigir e não reclassifica. A seção nova não pode
    /// exibir nem reinterpretar o nível.
    #[test]
    fn the_code_section_never_reclassifies_the_severity() {
        let finding = Vulnerability {
            title: "Achado alto".to_string(),
            severity: Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            code_location: Some(crate::domain::vulnerability::CodeLocation {
                file: "src/app.py".to_string(),
                line: 1,
                snippet: String::new(),
            }),
            code_remediation: vec!["Corrija no código".to_string()],
            ..Default::default()
        };

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[finding],
            &[],
            None,
            "",
            &[],
        );

        // O cabeçalho da seção repete o rótulo do scanner, e nenhum outro
        // nível aparece na seção de código.
        let section = report
            .split("## Localização no código")
            .nth(1)
            .expect("a seção de código deve existir");
        assert!(section.contains("ALTA"), "{section}");
        for forbidden in ["CRÍTICA", "MÉDIA", "BAIXA", "INFORMATIVA"] {
            assert!(
                !section.contains(forbidden),
                "a seção de código introduziu o nível {forbidden}: {section}"
            );
        }
    }

    fn vulnerability(severity: Severity, title: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta 3000".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            code_location: None,
            code_remediation: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            origins: Vec::new(),
        }
    }

    /// Tabela de caracteres: o que precisa ser escapado e o que não pode ser.
    ///
    /// A segunda coluna é o que o leitor precisa enxergar; a primeira garante que
    /// nenhum caractere de sintaxe sobreviva sem escape.
    #[test]
    fn escape_covers_markdown_syntax_without_touching_legitimate_text() {
        let escapados = [
            ('\\', "\\\\", "barra invertida"),
            ('`', "\\`", "código"),
            ('*', "\\*", "ênfase"),
            ('_', "\\_", "ênfase"),
            ('[', "\\[", "link"),
            (']', "\\]", "link"),
            ('<', "\\<", "tag HTML de abertura"),
            ('>', "\\>", "tag HTML de fechamento"),
            ('|', "\\|", "célula de tabela"),
            ('~', "\\~", "tachado"),
        ];
        for (entrada, esperado, rotulo) in escapados {
            assert_eq!(
                escape_markdown(&entrada.to_string()),
                esperado,
                "caractere {rotulo} ({entrada:?}) não foi escapado"
            );
        }

        // Texto legítimo do relatório em pt-BR precisa sair intacto.
        for legitimo in [
            "Injeção de SQL no parâmetro de busca",
            "Servidor: nginx/1.24.0 (Ubuntu)",
            "Endpoint http://alvo.local/api/v1/usuários",
            "Severidade alta — impacto no formulário de login",
            "CVE-2024-1234",
            "3.14 e 80% de confiança",
            "faixa pt-BR de --filtro até +filtro",
        ] {
            assert_eq!(
                escape_markdown(legitimo),
                legitimo,
                "escape quebrou texto legítimo: {legitimo:?}"
            );
        }
    }

    /// Um segredo lido do código do alvo não pode sobreviver no relatório.
    #[test]
    fn the_report_redacts_secrets_found_in_the_code() {
        let finding = Vulnerability {
            title: "Segredo exposto".to_string(),
            severity: Severity::Critical,
            description: "Descrição".to_string(),
            tool: "TruffleHog".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            code_location: Some(crate::domain::vulnerability::CodeLocation {
                file: "src/config.py".to_string(),
                line: 2,
                snippet: "EXEMPLO_SECRET=valor-de-exemplo".to_string(),
            }),
            code_remediation: vec!["Remova EXEMPLO_SECRET=valor-de-exemplo".to_string()],
            ..Default::default()
        };

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[finding],
            &[],
            None,
            "",
            &[],
        );

        assert!(!report.contains("valor-de-exemplo"), "{report}");
        assert!(report.contains("[REDACTED]"), "{report}");
    }

    #[test]
    fn only_line_leading_characters_get_the_block_prefix_escape() {
        // No meio do texto, `-` e `#` são texto comum e não são escapados.
        assert_eq!(
            escape_markdown_block("pt-BR - versão #2"),
            "pt-BR - versão #2"
        );
        // No início da linha, viram lista e cabeçalho se não forem escapados.
        assert_eq!(
            escape_markdown_block("## Seção injetada"),
            "\\## Seção injetada"
        );
        assert_eq!(escape_markdown_block("- item forjado"), "\\- item forjado");
        assert_eq!(escape_markdown_block("+ item forjado"), "\\+ item forjado");
        assert_eq!(
            escape_markdown_block("> citação forjada"),
            "\\> citação forjada"
        );
        // Um parágrafo com várias linhas trata cada linha como possível início.
        assert_eq!(
            escape_markdown_block("primeira\n## segunda"),
            "primeira\n\\## segunda"
        );
    }

    #[test]
    fn escape_neutralizes_markdown_injection_in_a_title() {
        // Um título que tentasse fechar o cabeçalho, abrir um link e injetar
        // HTML não pode virar nenhum desses três no Markdown gerado.
        let titulo = "SQLi\n## Seção injetada\n[clique](http://malvado.local) <img src=x>";
        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[vulnerability(Severity::High, titulo)],
            &[],
            None,
            "",
            &[],
        );

        // A quebra de linha vira espaço: o título não desloca a linha seguinte.
        assert!(!report.contains("\n## Seção injetada"), "{report}");
        // Toda marcação fica escapada. O texto cru continua no arquivo — o que
        // um leitor de Markdown mostra é a sequência sem a barra.
        assert!(report.contains("\\[clique\\]"), "{report}");
        assert!(report.contains("\\<img src=x\\>"), "{report}");
        // E o leitor de fato enxerga o caractere original, sem barra invertida.
        let rendered = unescape_markdown(&report);
        assert!(rendered.contains("[clique](http://malvado.local) <img src=x>"));
        assert!(
            rendered.contains("Seção injetada"),
            "o texto sumiu: {rendered}"
        );
    }

    #[test]
    fn injected_block_structure_stays_inside_the_description() {
        let mut finding = vulnerability(Severity::High, "Título normal");
        finding.description = "## Resumo executivo forjado\n- severidade inventada".to_string();

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[finding],
            &[],
            None,
            "",
            &[],
        );

        assert!(report.contains("\\## Resumo executivo forjado"), "{report}");
        assert!(report.contains("\\- severidade inventada"), "{report}");
        // Só as seções reais do relatório podem começar com `## `; nada que
        // venha do scanner consegue abrir uma seção nova.
        let secoes = [
            "## Resumo",
            "## Pontos Críticos",
            "## Todas as Vulnerabilidades",
            "## Localização no código",
            "## Proveniência dos achados",
        ];
        for linha in report.lines() {
            if linha.starts_with("## ") {
                assert!(secoes.contains(&linha), "seção forjada: {linha:?}");
            }
        }
    }

    #[test]
    fn escape_collapses_newlines_so_a_title_cannot_break_the_structure() {
        assert_eq!(escape_markdown("a\r\nb\tc"), "a  b c");
        assert_eq!(escape_markdown_block("a\nb"), "a\nb");
    }

    #[test]
    fn unescape_reverses_escape_for_every_escapable_character() {
        for character in MARKDOWN_ESCAPABLE {
            let original = character.to_string();
            assert_eq!(
                unescape_markdown(&escape_markdown(&original)),
                original,
                "escape/unescape não fecham para {character:?}"
            );
        }
        // O que o leitor vê é o caractere original, não a sequência escapada.
        assert_eq!(unescape_markdown(&escape_markdown("a*b")), "a*b");
        assert_eq!(unescape_markdown(&escape_markdown("<b>")), "<b>");
        // Uma barra que não precede um caractere escapável é preservada.
        assert_eq!(unescape_markdown("C:\\temp"), "C:\\temp");
        assert_eq!(unescape_markdown("barra final \\"), "barra final \\");
    }

    #[test]
    fn redaction_marker_is_not_escaped() {
        assert_eq!(escape_markdown("[REDACTED]"), "[REDACTED]");
    }

    #[test]
    fn report_includes_the_ai_analysis() {
        let analysis = "O alvo expõe um formulário sem proteção contra CSRF.\n\n \
                        Recomendo validar a origem de cada requisição.";

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            None,
            analysis,
            &[],
        );

        assert!(report.contains("## Análise da IA"), "{report}");
        assert!(report.contains("sem proteção contra CSRF"), "{report}");
        assert!(report.contains("validar a origem"), "{report}");
    }

    /// A análise da IA é o único trecho do relatório produzido por um modelo, e
    /// um modelo pode parafrasear o valor de um segredo detectado em vez de
    /// copiá-lo. O relatório é o artefato que circula fora do ambiente
    /// controlado, então a sanitização roda antes da escrita.
    #[test]
    fn report_redacts_a_secret_echoed_by_the_ai() {
        let analysis = "O login aceita password=hunter2 em texto puro.";

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            None,
            analysis,
            &[],
        );

        assert!(!report.contains("hunter2"), "{report}");
        assert!(report.contains("[REDACTED]"), "{report}");
    }

    #[test]
    fn report_omits_the_ai_section_when_there_is_no_analysis() {
        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            None,
            "   \n",
            &[],
        );
        assert!(!report.contains("## Análise da IA"), "{report}");
    }

    #[test]
    fn report_lists_failed_executions_with_tool_status_and_duration() {
        let mut execution = SecurityTool::new("Nikto", "--host alvo");
        execution.status = "failed".to_string();
        execution.duration_ms = 1_500;
        execution.execution_error = Some("exit status 1".to_string());

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            None,
            "",
            std::slice::from_ref(&execution),
        );

        assert!(report.contains("## Execuções com falha"), "{report}");
        assert!(report.contains("Ferramenta: Nikto"), "{report}");
        assert!(report.contains("Status: failed"), "{report}");
        assert!(report.contains("Duração: 1500 ms"), "{report}");
        assert!(report.contains("Erro: exit status 1"), "{report}");
    }

    #[test]
    fn report_omits_the_failure_section_when_every_execution_succeeded() {
        let mut execution = SecurityTool::new("Nmap", "--host alvo");
        execution.status = "success".to_string();
        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[],
            &[],
            None,
            "",
            std::slice::from_ref(&execution),
        );
        assert!(!report.contains("## Execuções com falha"), "{report}");
    }

    #[test]
    fn report_counts_informational_findings() {
        let finding = Vulnerability {
            title: "Porta aberta".to_string(),
            severity: Severity::Info,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta 3000".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        };

        let report = ReportGenerator::compile_report(
            &Configuration::default(),
            &[finding],
            &[],
            None,
            "",
            &[],
        );

        assert!(report.contains("- Total de vulnerabilidades: 1"));
        assert!(report.contains("- Informativas: 1"));
    }

    #[test]
    fn report_never_contains_credentials_or_raw_http_payloads() {
        let config = Configuration {
            target_url: "https://user:secret@target.local/path?token=secret".to_string(),
            ..Configuration::default()
        };
        let finding = Vulnerability {
            title: "Cabeçalhos".to_string(),
            severity: Severity::High,
            description: "request: Authorization: Bearer secret".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Remova o segredo".to_string(),
            didactic: "response: Set-Cookie: token=secret".to_string(),
            source: FindingSource::Real,
            target: "https://target.local/path?token=secret".to_string(),
            evidence: "request: GET /private?token=secret".to_string(),
            detected_at: "2026-09-06T12:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        };

        let report = ReportGenerator::compile_report(&config, &[finding], &[], None, "", &[]);

        assert!(!report.contains("secret"));
        assert!(!report.contains("?token="));
        assert!(!report.contains("request:"));
        assert!(!report.contains("response:"));
        assert!(report.contains("[REDACTED]"));
    }
}
