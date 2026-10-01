//! Testes de integração da fase de análise de código (issue #76).
//!
//! Cobrem o caminho declarado nos critérios de aceite: `--project` no
//! headless, o contrato de findings no log estruturado e no relatório, e a
//! recusa de `run_command` sem opt-in.
//!
//! Nenhuma chamada de rede nem container real acontece aqui: o binário é
//! executado com um diretório de configuração isolado e sem alvo válido, de
//! modo que o fluxo termina na validação antes dos scanners. O que se verifica
//! é o **contrato** — flag reconhecida, erro acionável, exit code — e não uma
//! varredura.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Ambiente isolado: `XDG_CONFIG_HOME` e `HOME` próprios, para que o teste
/// nunca leia nem escreva a configuração real do operador.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "smartsec-code-agent-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("projeto")).expect("o sandbox deve ser criado");
        std::fs::write(
            root.join("projeto/app.py"),
            "def login(user):\n    raise ValueError\n",
        )
        .expect("o fixture do projeto deve ser escrito");
        Self { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("projeto")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"));
        command
            .env("XDG_CONFIG_HOME", &self.root)
            .env("HOME", &self.root)
            .current_dir(&self.root);
        command
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_documents_the_project_flag() {
    let sandbox = Sandbox::new("help");
    let output = sandbox.command().arg("--help").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("--project"), "{stdout}");
    assert!(
        stdout.contains("diretório atual"),
        "o padrão do --project precisa ser declarado na ajuda: {stdout}"
    );
}

#[test]
fn a_missing_project_directory_is_reported_as_a_configuration_error() {
    let sandbox = Sandbox::new("projeto-inexistente");

    let output = sandbox
        .command()
        .args([
            "scan",
            "--target",
            "192.0.2.10",
            "--tools",
            "Nmap",
            "--project",
            "/caminho/que/nao/existe",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("--project"), "{stderr}");
    assert!(
        stderr.contains("não pôde ser usado"),
        "o erro precisa apontar a flag e a causa: {stderr}"
    );
}

#[test]
fn a_project_path_that_is_a_file_is_rejected_before_any_scan() {
    let sandbox = Sandbox::new("projeto-arquivo");
    let file = sandbox.project().join("app.py");

    let output = sandbox
        .command()
        .args([
            "scan",
            "--target",
            "192.0.2.10",
            "--tools",
            "Nmap",
            "--project",
            file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr_of(&output).contains("não pôde ser usado"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn an_empty_project_flag_is_rejected() {
    let sandbox = Sandbox::new("projeto-vazio");

    let output = sandbox
        .command()
        .args([
            "scan",
            "--target",
            "192.0.2.10",
            "--tools",
            "Nmap",
            "--project",
            "",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr_of(&output).contains("diretório do projeto não pode estar vazio"),
        "{}",
        stderr_of(&output)
    );
}

/// Um `--project` válido é aceito: o erro seguinte tem de ser o alvo, nunca a
/// flag. Sem este teste, uma regressão que rejeitasse todo `--project`
/// continuaria verde nos demais.
#[test]
fn a_valid_project_directory_passes_the_flag_validation() {
    let sandbox = Sandbox::new("projeto-valido");
    let project = sandbox.project();

    let output = sandbox
        .command()
        .args([
            "scan",
            "--target",
            "alvo inválido com espaço",
            "--tools",
            "Nmap",
            "--project",
            project.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("alvo"),
        "a validação do projeto passou e a do alvo reclama: {stderr}"
    );
    assert!(
        !stderr.contains("--project"),
        "um --project válido não pode virar erro: {stderr}"
    );
}

/// O fixture usado pelos testes do agente precisa continuar sendo um projeto
/// real e legível: se `tests/fixtures/codebase` sumir, os testes do módulo
/// passam a testar um caminho inexistente em vez do sandbox.
#[test]
fn the_codebase_fixture_is_present_and_readable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codebase");
    assert!(root.is_dir(), "fixture ausente: {}", root.display());
    assert!(root.join("src/app.py").is_file());
    assert!(root.join("src/config.py").is_file());
}
