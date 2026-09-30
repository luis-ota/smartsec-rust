//! Integração do histórico consultável pela CLI (issue #24, REQ19).
//!
//! Cada teste isola `XDG_CONFIG_HOME`/`HOME` para que o histórico semeado em
//! `smartsec/scans/` não dependa nem contamine a máquina de quem executa.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Raiz isolada por teste: `dirs::config_dir()` respeita `XDG_CONFIG_HOME`.
fn isolated_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "smartsec-historico-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("smartsec").join("scans"))
        .expect("o diretório de histórico isolado deve ser criado");
    root
}

fn command_in(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"));
    command
        .env("XDG_CONFIG_HOME", root)
        .env("HOME", root)
        .current_dir(root);
    command
}

/// Registro completo, no formato persistido por `save_scan_log`.
fn record_json(scan_id: &str, completed_at: &str, target: &str) -> String {
    format!(
        r#"{{
  "scan_id": "{scan_id}",
  "target_url": "{target}",
  "started_at": "2026-09-06T10:00:00Z",
  "completed_at": "{completed_at}",
  "execution_type": "Auto",
  "llm_provider": "Ollama",
  "tools_executed": [
    {{
      "tool_name": "Nmap",
      "arguments": ["-sT"],
      "executed_at": "2026-09-06T10:01:00Z",
      "output_bytes": 42,
      "output_sample": "",
      "stdout": "",
      "stderr": "",
      "status": "succeeded",
      "duration_ms": 1500,
      "tool_version": "7.94",
      "image": "docker.io/library/nmap:7.94",
      "execution_error": null,
      "podman_trace": []
    }}
  ],
  "findings_count": 2,
  "critical_count": 0,
  "high_count": 1,
  "medium_count": 0,
  "low_count": 0,
  "findings": [
    {{"title": "Versão desatualizada", "severity": "High", "tool": "Nmap"}},
    {{"title": "Cookie sem flag", "severity": "Info", "tool": "Nuclei"}}
  ],
  "agent_analysis": "A superfície web expõe serviços com versões antigas."
}}"#
    )
}

/// Versão anterior do formato: sem `info_count`, sem `decisions`, sem `podman_trace`.
fn legacy_record_json(scan_id: &str) -> String {
    format!(
        r#"{{
  "scan_id": "{scan_id}",
  "target_url": "http://legado.local",
  "started_at": "2026-09-01T10:00:00Z",
  "completed_at": "2026-09-01T10:05:00Z",
  "execution_type": "Assisted",
  "llm_provider": "Ollama",
  "tools_executed": [],
  "findings_count": 0,
  "critical_count": 0,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0,
  "findings": [],
  "agent_analysis": "Análise legada."
}}"#
    )
}

fn seed(root: &Path, scan_id: &str, content: &str) -> PathBuf {
    let path = root
        .join("smartsec")
        .join("scans")
        .join(format!("{scan_id}.json"));
    std::fs::write(&path, content).expect("o registro de teste deve ser gravado");
    path
}

/// Fotografia byte a byte do histórico para provar que a consulta é somente leitura.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("diretório de histórico legível")
        .map(|entry| {
            let path = entry.expect("entrada legível").path();
            let name = path
                .file_name()
                .expect("entrada nomeada")
                .to_string_lossy()
                .into_owned();
            (name, std::fs::read(&path).expect("conteúdo legível"))
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn history_lists_executions_from_the_newest_to_the_oldest() {
    let root = isolated_root("listagem");
    let scans = root.join("smartsec").join("scans");
    seed(
        &root,
        "scan_1757000000000000001",
        &record_json(
            "scan_1757000000000000001",
            "2026-09-06T10:05:00Z",
            "http://antigo.local",
        ),
    );
    seed(
        &root,
        "scan_1757000000000000003",
        &record_json(
            "scan_1757000000000000003",
            "2026-09-08T10:05:00Z",
            "http://recente.local",
        ),
    );
    seed(
        &root,
        "scan_1757000000000000002",
        &record_json(
            "scan_1757000000000000002",
            "2026-09-07T10:05:00Z",
            "http://medio.local",
        ),
    );
    let before = snapshot(&scans);

    let output = command_in(&root).arg("history").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("3 de 3 execuções"), "{stdout}");
    let newest = stdout
        .find("scan_1757000000000000003")
        .expect("mais recente");
    let middle = stdout
        .find("scan_1757000000000000002")
        .expect("intermediária");
    let oldest = stdout
        .find("scan_1757000000000000001")
        .expect("mais antiga");
    assert!(newest < middle && middle < oldest, "{stdout}");
    assert!(
        stdout.contains("concluída em 2026-09-08T10:05:00Z"),
        "{stdout}"
    );
    assert!(stdout.contains("1 alta"), "{stdout}");
    assert_eq!(
        snapshot(&scans),
        before,
        "a listagem não pode alterar os artefatos originais"
    );
}

#[test]
fn history_respects_the_configured_limit() {
    let root = isolated_root("limite");
    for index in 1..=4 {
        let scan_id = format!("scan_175700000000000000{index}");
        seed(
            &root,
            &scan_id,
            &record_json(&scan_id, "2026-09-06T10:05:00Z", "http://alvo.local"),
        );
    }

    let output = command_in(&root)
        .args(["history", "--limit", "2"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("2 de 4 execuções"), "{stdout}");
    assert!(stdout.contains("--limit"), "{stdout}");
}

#[test]
fn history_without_a_limit_is_rejected_instead_of_hiding_records() {
    let root = isolated_root("limite_invalido");

    for value in ["0", "abc"] {
        let output = command_in(&root)
            .args(["history", "--limit", value])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "limite {value}");
        let stderr = stderr_of(&output);
        assert!(stderr.contains("limite"), "{stderr}");
    }

    let output = command_in(&root)
        .arg("history")
        .arg("--limite")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr_of(&output).contains("exige um valor"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn history_of_an_empty_directory_explains_how_to_create_records() {
    let root = isolated_root("vazio");

    let output = command_in(&root).arg("history").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("vazio"), "{stdout}");
    assert!(stdout.contains("smartsec show"), "{stdout}");
}

#[test]
fn history_reports_unreadable_records_instead_of_hiding_them() {
    let root = isolated_root("corrompido");
    let scans = root.join("smartsec").join("scans");
    seed(
        &root,
        "scan_1757000000000000001",
        &record_json(
            "scan_1757000000000000001",
            "2026-09-06T10:05:00Z",
            "http://valido.local",
        ),
    );
    let broken = seed(&root, "scan_1757000000000000002", "{isto nao e json");
    let before = snapshot(&scans);

    let output = command_in(&root).arg("history").output().unwrap();

    // O registro legível continua listado e o ilegível é reportado, nunca sumido.
    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("scan_1757000000000000001"), "{stdout}");
    assert!(stdout.contains("ATENÇÃO"), "{stdout}");
    assert!(stdout.contains("scan_1757000000000000002.json"), "{stdout}");
    assert_eq!(
        snapshot(&scans),
        before,
        "nem o registro corrompido pode ser reescrito pela listagem"
    );

    // Abrir o registro corrompido é um erro de consulta, não um sucesso vazio.
    let output = command_in(&root)
        .arg("show")
        .arg("scan_1757000000000000002")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("Falha ao interpretar"), "{stderr}");
    assert!(stderr.contains("corrompido"), "{stderr}");
    assert!(broken.exists());
}

#[test]
fn show_opens_a_recorded_execution_with_its_findings_analysis_and_tools() {
    let root = isolated_root("detalhe");
    let scans = root.join("smartsec").join("scans");
    seed(
        &root,
        "scan_1757000000000000001",
        &record_json(
            "scan_1757000000000000001",
            "2026-09-06T10:05:00Z",
            "http://alvo.local",
        ),
    );
    let before = snapshot(&scans);

    let output = command_in(&root)
        .arg("show")
        .arg("scan_1757000000000000001")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("Ferramentas executadas"), "{stdout}");
    assert!(stdout.contains("Nmap"), "{stdout}");
    assert!(stdout.contains("succeeded"), "{stdout}");
    assert!(stdout.contains("Achados"), "{stdout}");
    assert!(stdout.contains("Versão desatualizada"), "{stdout}");
    assert!(stdout.contains("ALTA"), "{stdout}");
    assert!(stdout.contains("Análise da IA"), "{stdout}");
    assert!(
        stdout.contains("A superfície web expõe serviços"),
        "{stdout}"
    );
    assert_eq!(
        snapshot(&scans),
        before,
        "abrir uma execução não pode alterar o artefato original"
    );
}

#[test]
fn show_reads_a_previous_version_of_the_record_format() {
    let root = isolated_root("versao_anterior");
    seed(
        &root,
        "scan_1757000000000000010",
        &legacy_record_json("scan_1757000000000000010"),
    );

    let output = command_in(&root)
        .arg("show")
        .arg("scan_1757000000000000010")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("Análise legada."), "{stdout}");
    assert!(stdout.contains("nenhuma ferramenta registrada"), "{stdout}");
}

#[test]
fn show_fails_with_code_2_when_the_id_does_not_exist() {
    let root = isolated_root("inexistente");
    seed(
        &root,
        "scan_1757000000000000001",
        &record_json(
            "scan_1757000000000000001",
            "2026-09-06T10:05:00Z",
            "http://alvo.local",
        ),
    );

    let output = command_in(&root)
        .arg("show")
        .arg("scan_1757000000000000009")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("não encontrada no histórico"), "{stderr}");
    assert!(!stderr.contains("1757000000000000001"), "{stderr}");
}

#[test]
fn show_rejects_path_traversal_and_ids_outside_the_pattern() {
    let root = isolated_root("traversal");
    seed(
        &root,
        "scan_1757000000000000001",
        &record_json(
            "scan_1757000000000000001",
            "2026-09-06T10:05:00Z",
            "http://alvo.local",
        ),
    );
    // Alvo tentado fora do diretório de histórico, com conteúdo decoy.
    let secret = root.join("segredo.json");
    std::fs::write(&secret, r#"{"scan_id":"fora"}"#).unwrap();

    for hostile in [
        "../../segredo",
        "../../../etc/passwd",
        "scan_../../segredo",
        "..%2fsegredo",
        "/etc/passwd",
        "scan_",
        "scan_abc",
        "scan_1757000000000000001.json",
        "",
    ] {
        let output = command_in(&root).arg("show").arg(hostile).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "id hostil deveria falhar com 2: {hostile}"
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("identificador de execução inválido"),
            "id {hostile}: {stderr}"
        );
        assert!(!stderr.contains("fora"), "id {hostile}: {stderr}");
    }

    // O arquivo fora do diretório nunca é lido.
    assert!(secret.exists());
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        r#"{"scan_id":"fora"}"#
    );
}

#[test]
fn help_documents_the_history_contract() {
    let root = isolated_root("ajuda");

    let output = command_in(&root).arg("--help").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("history"), "{stdout}");
    assert!(stdout.contains("show <SCAN_ID>"), "{stdout}");
    assert!(stdout.contains("--limit"), "{stdout}");
}

#[test]
fn unknown_verb_still_reports_the_known_options() {
    let root = isolated_root("verbo");

    let output = command_in(&root).arg("historico").output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("comando desconhecido"), "{stderr}");
    assert!(stderr.contains("--help"), "{stderr}");
}
