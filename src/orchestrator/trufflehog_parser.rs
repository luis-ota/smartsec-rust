use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::tools::trufflehog::REPOSITORY_MOUNT_PATH;
use crate::utils::redaction::sanitize_evidence_component;
use serde::Deserialize;
use std::collections::HashSet;

/// Título e evidência são limitados para caber no relatório sem truncar a
/// informação essencial do achado.
const TITLE_LIMIT: usize = 120;

/// Registro JSONL emitido pelo TruffleHog no stdout com `--json`.
///
/// ## Allow-list deliberada
///
/// O objeto do TruffleHog carrega o **valor completo do segredo** em três
/// campos: `Raw`, `RawV2` e `SecretParts`. Esses campos **não são
/// desserializados aqui** — não existem nesta estrutura, então não há como
/// alcançarem um finding, um log, um relatório ou a evidência versionada.
///
/// Como isso foi medido, não presumido: em container real, um registro de
/// chave privada privada chegou ao stdout com
/// `"Raw":"-----BEGIN RSA PRIVATE KEY-----\nMIIE<MASCARADO>…"` e
/// `"SecretParts":{"token":"-----BEGIN RSA PRIVATE KEY-----\n…"}`
/// (ver `docs/evidence/issue-18-trufflehog.md`). O `serde` ignora campos não
/// declarados, o que torna a ausência do segredo uma propriedade da estrutura
/// de dados, não uma disciplina de codificação que alguém pode contornar com
/// um `..field`.
///
/// O campo `Redacted` do TruffleHog também não é lido: ele truca o segredo no
/// meio e não é estável entre versões, então não serve como evidência.
#[derive(Deserialize, Debug)]
struct TruffleHogResult {
    /// Metadados da fonte onde o segredo foi encontrado.
    #[serde(default)]
    #[serde(rename = "SourceMetadata")]
    source_metadata: SourceMetadata,
    /// Nome do detector que identificou o segredo.
    #[serde(default)]
    #[serde(rename = "DetectorName")]
    detector_name: String,
    /// `true` quando o segredo foi confirmado válido pela API do provedor.
    #[serde(default)]
    #[serde(rename = "Verified")]
    verified: bool,
}

/// Metadados da fonte do achado.
#[derive(Deserialize, Debug, Default)]
struct SourceMetadata {
    #[serde(default)]
    #[serde(rename = "Data")]
    data: SourceData,
}

/// Fonte concreta: sistema de arquivos ou repositório git.
///
/// As duas são lidas porque o subcomando `git` do TruffleHog é usado tanto para
/// `file://` quanto para uma URL remota, e o formato do registro muda conforme a
/// origem. `Filesystem` e `Git` são structs distintas justamente para que o
/// campo `file`/`line` seja lido de onde ele realmente existe.
#[derive(Deserialize, Debug, Default)]
struct SourceData {
    #[serde(default)]
    #[serde(rename = "Filesystem")]
    filesystem: Option<FilesystemSource>,
    #[serde(default)]
    #[serde(rename = "Git")]
    git: Option<GitSource>,
}

/// Origem em sistema de arquivos.
#[derive(Deserialize, Debug)]
struct FilesystemSource {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: Option<u64>,
}

/// Origem em repositório git.
#[derive(Deserialize, Debug)]
struct GitSource {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: Option<u64>,
    /// Commit em que o segredo aparece.
    #[serde(default)]
    commit: String,
    /// URI do repositório, ausente em registros antigos.
    #[serde(default)]
    repository: String,
}

/// Local preservado do achado, para a evidência.
#[derive(Debug, PartialEq, Eq)]
struct Origin {
    file: String,
    line: Option<u64>,
    commit: String,
    repository: String,
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

/// Traduz a verificação do TruffleHog para a severidade do SmartSec.
///
/// A verificação é a única informação estruturada de confiança que o scanner
/// publica, então ela define a severidade — nunca o texto do segredo, que além
/// de não existir aqui não poderia ser interpretado com segurança.
///
/// O caso `unknown` merece registro: o TruffleHog rebaixa para `unverified`
/// quando a verificação falha **sem erro** quando a rede não responde
/// (medido: 3 tentativas, 3,58 s, mesmo resultado e nenhum aviso). Como a
/// integração roda com `--no-verification`, um `Verified: false` significa
/// "detectado, não verificado" e nunca "inválido". A severidade reflete essa
/// incerteza em vez de tratar o achado como falso positivo descartável.
fn severity_for(verified: bool) -> Severity {
    if verified {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Extrai a origem preservando arquivo, linha e commit quando existirem.
///
/// O `file` do TruffleHog é o caminho **dentro do container** (medido:
/// `/alvo/config/credenciais.env`), porque o scanner só enxerga o repositório pelo
/// ponto de montagem. Esse prefixo é detalhe da implementação do executor, e
/// incharia a evidência com um diretório que não existe para quem lê o
/// relatório. O caminho é relativo ao repositório, que é o que o usuário
/// precisa abrir.
fn origin_of(metadata: &SourceMetadata) -> Origin {
    if let Some(git) = &metadata.data.git {
        return Origin {
            file: repository_relative(&git.file),
            line: git.line,
            commit: git.commit.clone(),
            repository: git.repository.clone(),
        };
    }
    if let Some(filesystem) = &metadata.data.filesystem {
        return Origin {
            file: repository_relative(&filesystem.file),
            line: filesystem.line,
            commit: String::new(),
            repository: String::new(),
        };
    }
    Origin {
        file: String::new(),
        line: None,
        commit: String::new(),
        repository: String::new(),
    }
}

/// Remove o ponto de montagem do container do caminho informado pelo scanner.
fn repository_relative(file: &str) -> String {
    let file = file.trim();
    if let Some(relative) = file.strip_prefix(REPOSITORY_MOUNT_PATH) {
        return relative.trim_start_matches('/').to_string();
    }
    file.to_string()
}

fn line_label(line: Option<u64>) -> String {
    line.map_or_else(|| "não informada".to_string(), |line| line.to_string())
}

fn commit_label(commit: &str) -> String {
    if commit.trim().is_empty() {
        "não informado".to_string()
    } else {
        commit.trim().to_string()
    }
}

fn repository_label(repository: &str) -> String {
    if repository.trim().is_empty() {
        "não informada".to_string()
    } else {
        repository.trim().to_string()
    }
}

/// Rótulo do valor de verificação, em pt-BR.
///
/// `verified: false` **não** significa que o segredo é inválido. Significa que
/// ele foi detectado e não confirmado — que, com `--no-verification`, é o
/// resultado esperado para todo achado. Dizer "não validado" evita que o
/// relatório sugira descartar o achado.
fn verification_label(verified: bool) -> &'static str {
    if verified {
        "confirmado pelo provedor"
    } else {
        "detectado, não validado"
    }
}

/// Parseia a saída JSONL do TruffleHog e retorna achados reais com proveniência
/// completa.
///
/// Preserva detector, arquivo, linha, commit e estado de verificação. O valor
/// do segredo nunca é lido nem propagado. Saída não-JSONL nunca é tratada como
/// varredura limpa.
#[allow(dead_code)]
pub fn parse_trufflehog_findings(output: &str, target: &str) -> Vec<Vulnerability> {
    parse_trufflehog_findings_with_errors(output, target).0
}

/// Retorna os achados e os erros da varredura.
///
/// O TruffleHog não emite array: cada linha do stdout é um registro independente
/// e uma linha malformada não invalida as demais. Ainda assim, saída que não
/// produz nenhum registro é reportada como erro, porque "nenhum segredo" e "a
/// varredura não produziu nada analisável" precisam ser distinguíveis no
/// relatório.
pub fn parse_trufflehog_findings_with_errors(
    output: &str,
    target: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let trimmed = output.trim();
    if trimmed.starts_with("[ERRO]") {
        return (
            Vec::new(),
            vec![
                "o TruffleHog não produziu resultados JSONL; a execução precisa ser revisada"
                    .to_string(),
            ],
        );
    }
    // Saída vazia com exit status 0 **é** a varredura limpa: nenhum segredo
    // encontrado, nenhum registro emitido. Isso foi medido no container, e é o
    // oposto do caso que parecia驱动器. O alvo inválido, que também produz
    // stdout vazio, é coberto por `--fail-on-scan-errors`, que faz o container
    // encerrar com status 1 e o executor prefixar a saída com `[ERRO]`.
    if trimmed.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut errors = Vec::new();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let detected_at = now_iso8601();

    for (index, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let result: TruffleHogResult = match serde_json::from_str(line) {
            Ok(result) => result,
            Err(error) => {
                errors.push(format!("registro {index} do TruffleHog inválido: {error}"));
                continue;
            }
        };

        let detector = result.detector_name.trim();
        if detector.is_empty() {
            errors.push(format!(
                "registro {index} do TruffleHog sem nome de detector foi descartado"
            ));
            continue;
        }

        let origin = origin_of(&result.source_metadata);
        let dedup_key = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            detector,
            origin.file,
            line_label(origin.line),
            result.verified
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        let severity = severity_for(result.verified);
        let line_text = line_label(origin.line);
        let commit = commit_label(&origin.commit);
        let repository = repository_label(&origin.repository);
        let verification = verification_label(result.verified);

        let file_label = if origin.file.trim().is_empty() {
            "não informada".to_string()
        } else {
            origin.file.trim().to_string()
        };

        let title = format!("Segredo exposto por {detector} em {file_label} (linha {line_text})");
        let description = format!(
            "O detector {detector} identificou um segredo exposto no arquivo {file_label}, linha {line_text}. Estado de verificação: {verification}. O valor do segredo não é preservado pelo SmartSec em nenhuma saída."
        );
        let recommendation = format!(
            "Confirme a exposição em {file_label} linha {line_text}, rotacione o segredo no provedor correspondente, remova o valor do histórico do repositório e revise quem teve acesso a ele."
        );
        let didactic = format!(
            "O TruffleHog identificou um segredo exposto com o detector {detector}.\n\nArquivo: {file_label}\nLinha: {line_text}\nVerificação: {verification}\n\nSeveridade atribuída pelo estado de verificação publicado pelo scanner: {}\n\nO SmartSec preserva detector, arquivo, linha e verificação, mas nunca o valor do segredo: ele não aparece em tela, log, relatório nem evidência. Trate a rotação do segredo como prioridade, porque mesmo um segredo não validado pode estar em uso.",
            severity.label_pt_br(),
        );

        let safe_detector = sanitize_evidence_component(detector);
        let safe_file = sanitize_evidence_component(&file_label);
        let safe_line = sanitize_evidence_component(&line_text);
        let safe_commit = sanitize_evidence_component(&commit);
        let safe_repository = sanitize_evidence_component(&repository);

        findings.push(Vulnerability {
            title: truncate(&title, TITLE_LIMIT),
            severity,
            description,
            tool: "TruffleHog".to_string(),
            recommendation,
            didactic,
            source: FindingSource::Real,
            target: target.to_string(),
            evidence: format!(
                "trufflehog detector: {safe_detector} | arquivo: {safe_file} | linha: {safe_line} | commit: {safe_commit} | repositório: {safe_repository} | verificado: {}",
                if result.verified { "sim" } else { "não" }
            ),
            detected_at: detected_at.clone(),
        });
    }

    if findings.is_empty() && errors.is_empty() {
        errors.push(
            "o TruffleHog terminou sem emitir nenhum resultado; confirme que o repositório foi montado corretamente e que existe histórico para analisar"
                .to_string(),
        );
    }

    (findings, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::trufflehog::container_arguments;

    const REAL: &str = include_str!("../../tests/fixtures/trufflehog/repositorio.jsonl");
    const NENHUM: &str = include_str!("../../tests/fixtures/trufflehog/nenhum_segredo.jsonl");
    const INVALIDO: &str = include_str!("../../tests/fixtures/trufflehog/invalido.jsonl");
    const DUPLICADO: &str = include_str!("../../tests/fixtures/trufflehog/duplicado.jsonl");

    const TARGET: &str = "/home/dev/projetos/repositorio";
    const MOUNT: &str = "/alvo";

    /// Segredo sintético plantado na fixture. É obviamente falso e nunca esteve
    /// em nenhum serviço, mas o teste exige que ele não vaze em nenhum campo.
    const SEGREDO_PLANTADO: &str = "CHAVE-DE-PRIVACAO-SINTETICA-NAO-USAR-000000000000";

    #[test]
    fn preserva_detector_arquivo_linha_e_verificacao() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(REAL, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|finding| finding.tool == "TruffleHog"));
        assert!(findings
            .iter()
            .all(|finding| finding.source == FindingSource::Real));
        assert!(findings.iter().all(|finding| finding.target == TARGET));

        let verified = findings
            .iter()
            .find(|finding| finding.evidence.contains("detector: AWS"))
            .expect("o detector AWS deve ser preservado");
        assert!(
            verified
                .evidence
                .contains("arquivo: config/credenciais.env"),
            "{}",
            verified.evidence
        );
        assert!(
            verified.evidence.contains("linha: 14"),
            "{}",
            verified.evidence
        );
        assert!(
            verified.evidence.contains("verificado: sim"),
            "{}",
            verified.evidence
        );
        assert_eq!(verified.severity, Severity::High);
    }

    #[test]
    fn achado_nao_verificado_preserva_o_registro_como_detectado() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(REAL, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let unverified = findings
            .iter()
            .find(|finding| finding.evidence.contains("detector: PrivateKey"))
            .expect("o detector de chave privada deve ser preservado");
        assert!(
            unverified.evidence.contains("verificado: não"),
            "{}",
            unverified.evidence
        );
        assert_eq!(unverified.severity, Severity::Medium);
        // `verified: false` não pode ser apresentado como segredo inválido.
        assert!(
            unverified.description.contains("não validado"),
            "{}",
            unverified.description
        );
    }

    #[test]
    fn o_valor_do_segredo_nunca_aparece_em_nenhum_campo_produzido() {
        // Entrada que carrega o segredo em Raw, RawV2 e SecretParts, como
        // aconteceu na execução real.
        let raw = format!(
            r#"{{"SourceMetadata":{{"Data":{{"Filesystem":{{"file":"/alvo/config/credenciais.env","line":14}}}}}},"SourceID":1,"SourceType":18,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS Access Key","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"{SEGREDO_PLANTADO}","RawV2":"{SEGREDO_PLANTADO}","Redacted":"{SEGREDO_PLANTADO}","ExtraData":{{}},"StructuredData":null,"SecretParts":{{"token":"{SEGREDO_PLANTADO}"}}}}"#
        );

        let (findings, errors) = parse_trufflehog_findings_with_errors(&raw, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        for (field, value) in [
            ("title", &finding.title),
            ("description", &finding.description),
            ("recommendation", &finding.recommendation),
            ("didactic", &finding.didactic),
            ("evidence", &finding.evidence),
            ("target", &finding.target),
        ] {
            assert!(
                !value.contains(SEGREDO_PLANTADO),
                "o segredo do TruffleHog vazou no campo {field}: {value}"
            );
        }
        // A fixture versionada também não pode conter o segredo em claro.
        assert!(
            !REAL.contains(SEGREDO_PLANTADO),
            "fixture versionada com segredo"
        );
    }

    #[test]
    fn o_valor_do_segredo_nao_vaza_pela_registro_completo() {
        let raw = format!(
            r#"{{"SourceMetadata":{{"Data":{{"Filesystem":{{"file":"/alvo/x","line":1}}}}}},"DetectorName":"Slack","Verified":true,"Raw":"{SEGREDO_PLANTADO}","RawV2":"{SEGREDO_PLANTADO}","SecretParts":{{"token":"{SEGREDO_PLANTADO}"}}}}"#
        );

        let (findings, _) = parse_trufflehog_findings_with_errors(&raw, TARGET);

        assert_eq!(findings.len(), 1);
        // `Raw`, `RawV2` e `SecretParts` não têm destino: nem os nomes dos
        // campos chegam à evidência.
        assert!(
            !findings[0].evidence.contains("Raw"),
            "{}",
            findings[0].evidence
        );
        assert!(
            !findings[0].evidence.contains("SecretParts"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn um_registro_git_preserva_commit_e_repositorio() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(REAL, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let from_git = findings
            .iter()
            .find(|finding| finding.evidence.contains("commit: 2aca944"))
            .expect("o commit deve ser preservado");
        assert!(
            from_git
                .evidence
                .contains("repositório: https://github.com/org/repo"),
            "{}",
            from_git.evidence
        );
        assert!(
            from_git.evidence.contains("arquivo: src/lib.rs"),
            "{}",
            from_git.evidence
        );
        assert!(
            from_git.evidence.contains("linha: 42"),
            "{}",
            from_git.evidence
        );
    }

    #[test]
    fn repositorio_sem_segredo_nao_e_erro_e_nao_produz_achado() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(NENHUM, TARGET);

        assert!(findings.is_empty(), "{findings:?}");
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn saida_vazia_e_a_varredura_limpa_que_o_container_real_produz() {
        // Medido: nenhum segredo encontrado sai com exit 0 e stdout vazio.
        // Reportar isso como erro transformaria um resultado legítimo em falha.
        for output in ["", "   ", "\n\n"] {
            let (findings, errors) = parse_trufflehog_findings_with_errors(output, TARGET);

            assert!(findings.is_empty(), "{output:?}");
            assert!(errors.is_empty(), "{output:?}: {errors:?}");
        }
    }

    #[test]
    fn saida_diagnostica_e_reportada_como_erro_de_execucao() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(
            "[ERRO] O container smartsec-abc encerrou com status 1",
            TARGET,
        );

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("não produziu resultados JSONL"),
            "{errors:?}"
        );
    }

    #[test]
    fn jsonl_invalido_e_reportado_em_vez_de_varrer_limpo() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(INVALIDO, TARGET);

        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("registro 0 do TruffleHog inválido"),
            "{errors:?}"
        );
    }

    #[test]
    fn uma_linha_malformada_nao_invalida_os_registros_validos() {
        // Registro válido, linha quebrada, registro válido: o JSONL é
        // independente por linha e o parser precisa ser tolerante.
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/a","line":1}}},"DetectorName":"AWS","Verified":false}"#,
            "\n",
            r#"{"SourceMetadata":{"Data":"quebrado"#,
            "\n",
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/b","line":2}}},"DetectorName":"GitHub","Verified":true}"#,
            "\n"
        );

        let (findings, errors) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert_eq!(findings.len(), 2, "{findings:?}");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("registro 1"), "{errors:?}");
    }

    #[test]
    fn deduplica_registros_repetidos() {
        let (findings, errors) = parse_trufflehog_findings_with_errors(DUPLICADO, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        let keys: HashSet<&str> = findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect();
        assert_eq!(
            keys.len(),
            findings.len(),
            "registros duplicados sobreviveram"
        );
    }

    #[test]
    fn registros_da_mesma_credencial_em_arquivos_distintos_sao_preservados() {
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/a.env","line":1}}},"DetectorName":"AWS","Verified":false}"#,
            "\n",
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/b.env","line":1}}},"DetectorName":"AWS","Verified":false}"#,
            "\n"
        );

        let (findings, _) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn registro_sem_detector_e_descartado_com_erro() {
        let raw = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/a","line":1}}},"Verified":false}"#;

        let (findings, errors) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert!(findings.is_empty());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("sem nome de detector"), "{errors:?}");
    }

    #[test]
    fn origem_ausente_nao_quebra_o_achado() {
        let raw = r#"{"SourceMetadata":{},"DetectorName":"SendGrid","Verified":true}"#;

        let (findings, errors) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].evidence.contains("arquivo: não informada"),
            "{}",
            findings[0].evidence
        );
        assert!(
            findings[0].evidence.contains("linha: não informada"),
            "{}",
            findings[0].evidence
        );
        assert!(
            findings[0].evidence.contains("commit: não informado"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn o_ponto_de_montagem_do_container_nao_vaza_para_a_evidencia() {
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/src/lib.rs","line":9}}},"DetectorName":"AWS","Verified":true}"#,
            "\n"
        );

        let (findings, _) = parse_trufflehog_findings_with_errors(raw, TARGET);

        // O scanner só enxerga `/alvo`, mas quem lê o relatório precisa abrir o
        // arquivo no repositório dele.
        assert!(
            findings[0].evidence.contains("arquivo: src/lib.rs"),
            "{}",
            findings[0].evidence
        );
        assert!(
            !findings[0].evidence.contains("/alvo"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn um_caminho_sem_o_prefixo_de_montagem_e_preservado() {
        // Repositório remoto: não existe `/alvo` para remover.
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Git":{"file":"config/app.yml","line":3,"commit":"abc1234","repository":"https://github.com/org/repo"}}},"DetectorName":"GitHub","Verified":true}"#,
            "\n"
        );

        let (findings, _) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert!(
            findings[0].evidence.contains("arquivo: config/app.yml"),
            "{}",
            findings[0].evidence
        );
    }

    #[test]
    fn a_severidade_vem_do_estado_de_verificacao_publicado_pelo_scanner() {
        assert_eq!(severity_for(true), Severity::High);
        assert_eq!(severity_for(false), Severity::Medium);
    }

    #[test]
    fn a_evidence_nao_carrega_credencial_nem_query_string() {
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/a.env?token=segredo","line":1}}},"DetectorName":"AWS","Verified":false,"Raw":"AKIAIOSFODNN7EXEMPLO"}"#,
            "\n"
        );

        let (findings, _) = parse_trufflehog_findings_with_errors(raw, TARGET);

        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert!(!evidence.contains("token="), "{evidence}");
        assert!(!evidence.contains("segredo"), "{evidence}");
        assert!(!evidence.contains("AKIA"), "{evidence}");
    }

    #[test]
    fn o_manifesto_usa_o_comando_validado_no_container() {
        let arguments = container_arguments(TARGET, MOUNT);

        assert!(arguments.contains(&"--json".to_string()));
        assert!(arguments.contains(&"--no-update".to_string()));
        assert!(arguments.contains(&"--no-verification".to_string()));
        assert!(arguments.contains(&"--fail-on-scan-errors".to_string()));
        assert!(arguments.iter().any(|argument| argument == "git"));
        assert!(arguments.iter().any(|argument| argument == "file:///alvo"));
    }
}
