//! Testes degolden do relatório: o Markdown byte a byte e o texto do PDF.
//!
//! O Markdown é comparado byte a byte com um golden versionado, porque
//! `compile_report` é determinístico: qualquer mudança no formato do relatório
//! é uma mudança de contrato e tem de ser explícita no diff.
//!
//! O PDF não pode ser comparado byte a byte: o `printpdf` grava identificadores
//! de objeto e um timestamp de criação que mudam a cada execução. O que é
//! determinístico — e é o que importa — é o *texto* do documento. O teste
//! então relê o PDF gerado com o próprio parser do `printpdf`, extrai o texto de
//! cada página e compara com um golden do texto que o leitor deve enxergar.
//! Assim a asserção é sobre o artefato real em disco, não sobre uma estrutura
//! interna, e sem depender do Poppler nem de qualquer binário do sistema.
//!
//! Limitação declarada: a extração reconstrói o texto a partir do `ToUnicode`
//! CMap do subconjunto da fonte. Ela valida o conteúdo visível, mas não a
//! posição exata de cada glifo nem a geometria da caixa — o layout é
//! verificado por [`crate::report::pdf`] (margem, quebra e subconjunto).

use super::generator::{escape_markdown, ReportGenerator};
use super::pdf;
use crate::config::Configuration;
use crate::domain::security_tool::SecurityTool;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::domain::Severity;
use crate::orchestrator::decision::{
    DecisionRecord, DecisionSource, NucleiPlan, NucleiTemplateProfile,
};
use std::collections::BTreeMap;

const MARKDOWN_GOLDEN: &str = include_str!("../../tests/fixtures/report/completo.md");
const PDF_TEXT_GOLDEN: &str = include_str!("../../tests/fixtures/report/completo.pdf.txt");

/// Cenário único e determinístico usado pelos dois goldens.
fn cenario() -> (
    Configuration,
    Vec<Vulnerability>,
    Vec<DecisionRecord>,
    String,
    Vec<SecurityTool>,
) {
    let config = Configuration {
        target_url: "http://alvo.local:8080/app".to_string(),
        execution_type: crate::config::execution_type::ExecutionType::Auto,
        ..Configuration::default()
    };

    let vulnerabilidades = vec![
        Vulnerability {
            title: "Injeção de SQL no parâmetro id".to_string(),
            severity: Severity::Critical,
            description: "O parâmetro `id` é concatenado na consulta sem \
                          parametrização, permitindo leitura da base."
                .to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Use consultas parametrizadas e valide o tipo do parâmetro."
                .to_string(),
            didactic: "Um invasor pode digitar comandos no campo de busca e ler \
                       dados de outros usuários."
                .to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local:8080/app?id=1".to_string(),
            evidence: "template: sqli/basic; matcher: time-based".to_string(),
            detected_at: "2026-09-30T14:05:00Z".to_string(),
            code_location: None,
            code_remediation: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            origins: Vec::new(),
        },
        Vulnerability {
            // Título com marcação e HTML: precisa chegar escapado no Markdown e
            //legível no PDF.
            title: "Cabeçalhos `Server` e *X-Powered-By* <div>".to_string(),
            severity: Severity::Medium,
            description: "Cabeçalhos revelam a pilha tecnológica do servidor.".to_string(),
            tool: "Nikto".to_string(),
            recommendation: "Remova os cabeçalhos de identificação.".to_string(),
            didactic: String::new(),
            source: FindingSource::Real,
            target: "http://alvo.local:8080".to_string(),
            evidence: "Server: nginx/1.24.0".to_string(),
            detected_at: "2026-09-30T14:05:01Z".to_string(),
            code_location: None,
            code_remediation: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            origins: Vec::new(),
        },
        Vulnerability {
            title: "Porta 8080 aberta".to_string(),
            severity: Severity::Info,
            description: "Serviço HTTP respondendo na porta 8080.".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Confirme se a porta deve estar exposta.".to_string(),
            didactic: String::new(),
            source: FindingSource::Real,
            target: "http://alvo.local:8080".to_string(),
            evidence: "8080/tcp open http".to_string(),
            detected_at: "2026-09-30T14:05:02Z".to_string(),
            code_location: None,
            code_remediation: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            origins: Vec::new(),
        },
    ];

    let decisoes = vec![DecisionRecord {
        source: DecisionSource::Ai,
        model: "gpt-4o".to_string(),
        justification: "A porta 80 respondeu e o 443 está fechado.".to_string(),
        parameters: BTreeMap::from([
            ("concurrency".to_string(), "10".to_string()),
            ("timeout".to_string(), "120".to_string()),
        ]),
        evidence: vec!["porta 80 fechada".to_string()],
        plan: NucleiPlan {
            should_run: true,
            profiles: vec![NucleiTemplateProfile::HttpMisconfiguration],
            concurrency: 10,
            timeout_seconds: 120,
        },
    }];

    let analise = "O alvo expõe um formulário de login sem proteção contra CSRF.\n\n\
                   Prioridade: corrigir a injeção de SQL antes de qualquer outra correção."
        .to_string();

    let mut falha = SecurityTool::new("Nikto", "--host http://alvo.local:8080");
    falha.status = "failed".to_string();
    falha.duration_ms = 1_500;
    falha.execution_error = Some("exit status 1: o scanner encontrou erro interno".to_string());

    (config, vulnerabilidades, decisoes, analise, vec![falha])
}

fn markdown_do_cenario() -> String {
    let (config, vulnerabilidades, decisoes, analise, falhas) = cenario();
    ReportGenerator::compile_report(
        &config,
        &vulnerabilidades,
        &decisoes,
        None,
        &analise,
        &falhas,
    )
}

/// Extrai o texto de cada página do PDF realmente gravado em `bytes`.
///
/// Não usa `PdfPage::extract_text` diretamente: o documento é relido do disco
/// pelo parser para que o teste valide o artefato, e não a estrutura em memória.
fn texto_do_pdf(bytes: &[u8]) -> String {
    let documento = printpdf::PdfDocument::parse(
        bytes,
        &printpdf::PdfParseOptions::default(),
        &mut Vec::new(),
    )
    .expect("o PDF gerado não pôde ser relido pelo parser do printpdf");
    documento
        .extract_text()
        .iter()
        .flatten()
        .map(|bloco| bloco.replace('\u{c}', " "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Versão do texto do PDF com todo o espaço em branco colapsado.
///
/// A tabela de severidades põe rótulo e valor em colunas separadas, então o
/// texto extraído os traz em linhas distintas. Para comparar semântica entre os
/// dois artefatos é preciso olhar o texto corrido, não linha a linha.
fn texto_plano(texto: &str) -> String {
    texto.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn markdown_bate_com_o_golden_byte_a_byte() {
    let produced = markdown_do_cenario();
    assert_eq!(
        produced, MARKDOWN_GOLDEN,
        "o Markdown do relatório mudou; o golden em tests/fixtures/report/ precisa \
         ser revisado junto com a mudança"
    );
}

#[test]
fn o_golden_do_markdown_e_reexecutavel() {
    // Guarda contra um golden colado de uma execução antiga: recompilar o
    // cenário precisa reproduzir exatamente o arquivo versionado.
    assert_eq!(markdown_do_cenario().len(), MARKDOWN_GOLDEN.len());
    assert!(markdown_do_cenario().ends_with('\n'), "falta newline final");
}

#[test]
fn o_markdown_contem_a_analise_da_ia_e_a_execucao_com_falha() {
    let markdown = markdown_do_cenario();
    assert!(markdown.contains("## Análise da IA"), "{markdown}");
    assert!(markdown.contains("sem proteção contra CSRF"), "{markdown}");
    assert!(markdown.contains("## Execuções com falha"), "{markdown}");
    assert!(markdown.contains("Ferramenta: Nikto"), "{markdown}");
    assert!(markdown.contains("Duração: 1500 ms"), "{markdown}");
}

#[test]
fn findings_informativos_continuam_sendo_contados_e_listados() {
    let markdown = markdown_do_cenario();
    assert!(
        markdown.contains("- Total de vulnerabilidades: 3"),
        "{markdown}"
    );
    assert!(markdown.contains("- Críticas: 1"), "{markdown}");
    assert!(markdown.contains("- Médias: 1"), "{markdown}");
    assert!(markdown.contains("- Informativas: 1"), "{markdown}");
    assert!(
        markdown.contains("- [INFORMATIVA] Porta 8080 aberta - Nmap"),
        "o finding Info sumiu da lista: {markdown}"
    );
}

#[test]
fn conteudo_dinamico_fica_escapado_no_markdown() {
    let markdown = markdown_do_cenario();
    // O título com `*`, backtick e `<div>` precisa estar escapado.
    assert!(
        markdown.contains("Cabeçalhos \\`Server\\` e \\*X-Powered-By\\* \\<div\\>"),
        "{markdown}"
    );
    // Nenhuma linha de conteúdo pode abrir uma seção fora do conjunto real.
    for linha in markdown.lines() {
        if linha.starts_with("## ") {
            assert!(
                [
                    "## Decisões Dinâmicas",
                    "## Análise da IA",
                    "## Resumo",
                    "## Pontos Críticos",
                    "## Todas as Vulnerabilidades",
                    "## Execuções com falha",
                    "## Localização no código",
                    "## Proveniência dos achados",
                ]
                .contains(&linha),
                "seção inesperada: {linha:?}"
            );
        }
    }
}

#[test]
fn o_golden_nao_contem_segredo_nem_query_string() {
    assert!(!MARKDOWN_GOLDEN.contains("?id=1"), "{MARKDOWN_GOLDEN}");
    assert!(!MARKDOWN_GOLDEN.contains("?token="), "{MARKDOWN_GOLDEN}");
    assert!(!PDF_TEXT_GOLDEN.contains("?id=1"), "{PDF_TEXT_GOLDEN}");
}

#[test]
fn pdf_gerado_tem_magic_bytes_e_nao_pode_ser_comparado_byte_a_byte() {
    let bytes = pdf::render(&markdown_do_cenario()).unwrap();
    assert!(bytes.starts_with(b"%PDF-"), "magic bytes ausentes");
    assert!(bytes.ends_with(b"%%EOF"), "PDF truncado");
    // Documenta por que o golden do PDF é o texto, não o arquivo: duas
    // execuções do mesmo relatório não produzem bytes idênticos.
    let segunda = pdf::render(&markdown_do_cenario()).unwrap();
    assert_ne!(
        bytes, segunda,
        "o PDF passou a ser determinístico; vale reavaliar o golden de texto"
    );
    assert_eq!(
        texto_do_pdf(&bytes),
        texto_do_pdf(&segunda),
        "o texto do PDF precisa ser estável entre execuções"
    );
}

#[test]
fn texto_do_pdf_bate_com_o_golden() {
    let bytes = pdf::render(&markdown_do_cenario()).unwrap();
    let extraido = texto_do_pdf(&bytes);
    assert_eq!(
        extraido.trim(),
        PDF_TEXT_GOLDEN.trim(),
        "o texto do PDF mudou; o golden em tests/fixtures/report/ precisa ser \
         revisado junto com a mudança"
    );
}

#[test]
fn o_pdf_mostra_o_texto_legivel_e_nao_o_escape() {
    let extraido = texto_do_pdf(&pdf::render(&markdown_do_cenario()).unwrap());
    // O leitor vê o caractere, não a sequência escapada do Markdown.
    assert!(
        extraido.contains("Cabeçalhos `Server` e *X-Powered-By* <div>"),
        "{extraido}"
    );
    assert!(
        !extraido.contains("\\<div\\>"),
        "o escape vazou para o PDF: {extraido}"
    );
    assert!(
        !extraido.contains("\\`"),
        "o escape vazou para o PDF: {extraido}"
    );
}

#[test]
fn o_pdf_preserva_os_acentos_do_portugues() {
    let extraido = texto_do_pdf(&pdf::render(&markdown_do_cenario()).unwrap());
    for trecho in [
        "Relatório de Análise de Segurança",
        "Decisões Dinâmicas",
        "Cabeçalhos",
        "Análise da IA",
        "Parâmetros",
        "Proveniência",
        "Execuções com falha",
        "MÉDIA",
        "INFORMATIVA",
    ] {
        assert!(
            extraido.contains(trecho),
            "trecho ausente no PDF: {trecho:?}\n{extraido}"
        );
    }
    assert!(
        !extraido.contains('\u{FFFD}'),
        "glifo sem mapeamento no PDF"
    );
}

#[test]
fn o_pdf_nao_diverge_do_markdown_nas_secoes() {
    let bytes = pdf::render(&markdown_do_cenario()).unwrap();
    let extraido = texto_do_pdf(&bytes);
    for secao in [
        "Análise da IA",
        "Resumo",
        "Pontos Críticos",
        "Todas as Vulnerabilidades",
        "Execuções com falha",
        "Proveniência dos achados",
    ] {
        assert!(
            extraido.contains(secao),
            "seção ausente no PDF: {secao}\n{extraido}"
        );
    }
    // Os números do resumo precisam ser os mesmos nos dois artefatos. A tabela
    // de severidades põe rótulo e valor em colunas, então a comparação é feita
    // sobre o texto corrido e sem os dois-pontos que o Markdown traz.
    let plano = texto_plano(&extraido);
    assert!(plano.contains("Total de vulnerabilidades 3"), "{plano}");
    assert!(plano.contains("Críticas 1"), "{plano}");
    assert!(plano.contains("Informativas 1"), "{plano}");
    assert!(plano.contains("Duração: 1500 ms"), "{plano}");

    // E nenhum número do resumo do Markdown pode sumir na conversão.
    for linha in [
        "- Total de vulnerabilidades: 3",
        "- Críticas: 1",
        "- Médias: 1",
        "- Informativas: 1",
    ] {
        let (rotulo, valor) = linha.trim_start_matches("- ").split_once(": ").unwrap();
        assert!(
            plano.contains(&format!("{} {}", rotulo, valor)),
            "o par {rotulo}/{valor} do .md não está no .pdf:\n{plano}"
        );
    }
}

#[test]
fn o_pdf_quebra_pagina_quando_o_relatorio_nao_cabe_em_uma() {
    let longo = "# Relatório\n\n".to_string()
        + &(0..160)
            .map(|indice| {
                format!(
                    "## Achado {indice}\n\nDescrição do achado {indice} com acentos: \
                     severidade alta, parâmetro vulnerável e correção sugerida.\n\n"
                )
            })
            .collect::<String>();
    let bytes = pdf::render(&longo).unwrap();
    let documento = printpdf::PdfDocument::parse(
        &bytes,
        &printpdf::PdfParseOptions::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(
        documento.pages.len() > 1,
        "o relatório longo não foi quebrado em páginas"
    );
    // Nenhum texto pode ser perdido na quebra.
    let extraido = texto_do_pdf(&bytes);
    assert!(extraido.contains("Achado 0"), "{extraido}");
    assert!(extraido.contains("Achado 159"), "{extraido}");
}

#[test]
fn a_fonte_entrada_no_pdf_e_a_noto_sans_com_cmap_unicode() {
    // LIMITAÇÃO CONHECIDA E MEDIDA: com `default-features = false` o printpdf
    // 0.12.8 NÃO subdefine a fonte. `font::subset_font` só faz o subconjunto na
    // configuração `text_layout`; sem ela a função devolve os bytes originais
    // inteiros (src/font.rs, `#[cfg(not(feature = "text_layout"))]`). Como
    // `text_layout` é justamente a feature que traria azul-layout e
    // rust-fontconfig, o relatório embute a Noto Sans completa a cada execução:
    // um PDF de uma página tem ~290 KB, quase todos da fonte comprimida.
    //
    // Este teste trava o comportamento real para que uma mudança de versão do
    // printpdf que passe a subdefinir a fonte apareça como falha a ser
    // investigada — e não como um bytes-menos silencioso.
    let bytes = pdf::render("# Curto\n").unwrap();
    let pequeno = bytes.len();
    let grande = pdf::render(&format!("# Ok\n\n{}\n", "palavra ".repeat(4000)))
        .unwrap()
        .len();
    assert!(
        grande < pequeno * 2,
        "o tamanho do PDF parou de depender do texto; o subconjunto pode \
         ter sido ativado (antes {pequeno} bytes, agora {grande})"
    );

    // O que não pode regredir: a fonte precisa estar embutida e com o texto
    // extraível, senão o PDF sai em branco num leitor qualquer.
    assert!(
        bytes.windows(10).any(|janela| janela == b"/FontFile2"),
        "a fonte não foi embutida"
    );
}

#[test]
fn o_escape_do_golden_bate_com_a_funcao_publica() {
    // Sanidade do fixture: o título escapado do golden é o que a função produz.
    assert_eq!(
        escape_markdown("Cabeçalhos `Server` e *X-Powered-By* <div>"),
        "Cabeçalhos \\`Server\\` e \\*X-Powered-By\\* \\<div\\>"
    );
}
