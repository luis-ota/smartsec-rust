use crate::config::Configuration;
use crate::domain::security_tool::SecurityTool;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::DecisionRecord;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn compile_report(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
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
            md.push_str(&escape_markdown_block(ai_analysis));
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
                "- [{}] {} - {}\n",
                v.severity.label_pt_br(),
                escape_markdown(&v.title),
                escape_markdown(&v.tool)
            ));
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

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

        let report =
            ReportGenerator::compile_report(&Configuration::default(), &[finding], &[], "", &[]);

        assert!(report.contains("\\## Resumo executivo forjado"), "{report}");
        assert!(report.contains("\\- severidade inventada"), "{report}");
        // Só as seções reais do relatório podem começar com `## `; nada que
        // venha do scanner consegue abrir uma seção nova.
        let secoes = [
            "## Resumo",
            "## Pontos Críticos",
            "## Todas as Vulnerabilidades",
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
                        Recomendo validar o token em cada requisição.";

        let report =
            ReportGenerator::compile_report(&Configuration::default(), &[], &[], analysis, &[]);

        assert!(report.contains("## Análise da IA"), "{report}");
        assert!(report.contains("sem proteção contra CSRF"), "{report}");
        assert!(report.contains("validar o token"), "{report}");
    }

    #[test]
    fn report_omits_the_ai_section_when_there_is_no_analysis() {
        let report =
            ReportGenerator::compile_report(&Configuration::default(), &[], &[], "   \n", &[]);
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
        };

        let report =
            ReportGenerator::compile_report(&Configuration::default(), &[finding], &[], "", &[]);

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
        };

        let report = ReportGenerator::compile_report(&config, &[finding], &[], "", &[]);

        assert!(!report.contains("secret"));
        assert!(!report.contains("?token="));
        assert!(!report.contains("request:"));
        assert!(!report.contains("response:"));
        assert!(report.contains("[REDACTED]"));
    }
}
