//! Contrato de ajuda e de erros de uso do subcomando `auth`.
//!
//! Nenhum teste deste arquivo toca no keyring real: `set`, `status` e `remove`
//! contra o cofre do sistema vivem em testes com `CredentialStore` em memória.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn isolated_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "smartsec-auth-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("a raiz isolada deve ser criada");
    root
}

fn command_in(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_smartsec"));
    command
        .env("XDG_CONFIG_HOME", root)
        .env("HOME", root)
        .env_remove("SMARTSEC_API_KEY")
        .current_dir(root);
    command
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn auth_help_documents_the_three_actions_and_the_stdin_contract() {
    let root = isolated_root("ajuda");

    let output = command_in(&root).args(["auth", "--help"]).output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("smartsec auth set"), "{stdout}");
    assert!(stdout.contains("smartsec auth status"), "{stdout}");
    assert!(stdout.contains("smartsec auth remove"), "{stdout}");
    assert!(stdout.contains("--stdin"), "{stdout}");
    assert!(stdout.contains("auth.json"), "{stdout}");
    assert!(stdout.contains("SMARTSEC_API_KEY"), "{stdout}");
}

#[test]
fn bare_auth_shows_help_instead_of_opening_the_tui() {
    let root = isolated_root("sem-argumentos");

    let output = command_in(&root).arg("auth").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout_of(&output).contains("Chave da API"),
        "{}",
        stdout_of(&output)
    );
}

#[test]
fn auth_set_help_is_the_auth_help() {
    let root = isolated_root("ajuda-set");

    let output = command_in(&root)
        .args(["auth", "set", "--help"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout_of(&output).contains("Chave da API"),
        "{}",
        stdout_of(&output)
    );
}

#[test]
fn auth_set_writes_private_auth_json_without_keyring() {
    let root = isolated_root("arquivo-local");
    let mut child = command_in(&root)
        .args(["auth", "set", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("processo");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"sk-teste-auth-json")
        .expect("chave");
    let output = child.wait_with_output().expect("saida");
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));

    let path = root.join("smartsec/auth.json");
    let content = std::fs::read_to_string(&path).expect("auth.json");
    assert!(content.contains("sk-teste-auth-json"), "{content}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let status = command_in(&root).args(["auth", "status"]).output().unwrap();
    let text = stdout_of(&status);
    assert!(text.contains("cadastrada"), "{text}");
    assert!(text.contains("auth.json"), "{text}");
    assert!(!text.to_lowercase().contains("bloqueado"), "{text}");

    let remove = command_in(&root).args(["auth", "remove"]).output().unwrap();
    assert_eq!(remove.status.code(), Some(0));
    assert!(!path.exists());
}

#[test]
fn auth_rejects_a_key_passed_as_an_argument_without_echoing_it() {
    let root = isolated_root("argumento");
    let secret = "sk-nao-pode-aparecer-em-argumento";

    let output = command_in(&root)
        .args(["auth", "set", secret])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(!stderr.contains(secret), "{stderr}");
    assert!(stderr.contains("linha de comando"), "{stderr}");
    assert!(stderr.contains("--stdin"), "{stderr}");
}

#[test]
fn auth_rejects_an_unknown_subcommand_without_echoing_the_argument() {
    let root = isolated_root("subcomando");

    let output = command_in(&root)
        .args(["auth", "exportar"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("auth set"), "{stderr}");
    assert!(!stderr.contains("exportar"), "{stderr}");
}

#[test]
fn global_help_lists_the_auth_command() {
    let root = isolated_root("ajuda-global");

    let output = command_in(&root).arg("--help").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("smartsec auth"), "{stdout}");
    assert!(stdout.contains("auth.json"), "{stdout}");
}
