use std::process::Command;

fn isolated_command() -> Command {
    let root = std::env::temp_dir().join(format!(
        "smartsec-exit-codes-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("o diretório isolado deve ser criado");
    let mut command = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"));
    command
        .env("XDG_CONFIG_HOME", &root)
        .env("HOME", &root)
        .current_dir(&root);
    command
}

#[test]
fn help_exits_with_code_0_and_documents_the_contract() {
    let output = isolated_command().arg("--help").output().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Códigos de saída"), "{stdout}");
    assert!(stdout.contains("--output-dir"), "{stdout}");
}

#[test]
fn configuration_error_exits_with_code_2() {
    let output = isolated_command()
        .args(["scan", "--target", "192.0.2.10", "--tools", "Inexistente"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ferramenta desconhecida"), "{stderr}");
}

#[test]
fn empty_output_dir_exits_with_code_2() {
    let output = isolated_command()
        .args(["scan", "--target", "192.0.2.10", "--output-dir", ""])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("diretório de saída não pode ser vazio"),
        "{stderr}"
    );
}
