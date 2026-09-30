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

#[test]
fn an_invalid_global_toml_is_reported_and_does_not_reset_silently() {
    let root = std::env::temp_dir().join(format!(
        "smartsec-invalid-global-toml-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let config_dir = root.join("smartsec");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    let broken = "target_url = \"http://alvo.local\"\nactive_tools = [\"Nmap\"\n";
    std::fs::write(&config_path, broken).unwrap();

    // `--target` na CLI é obrigatório e independe do arquivo global, então o
    // run continua para exercitar o aviso de parsing na saída real.
    let output = isolated_command()
        .args(["scan", "--target", "192.0.2.10", "--tools", "Inexistente"])
        .env("XDG_CONFIG_HOME", &root)
        .env("HOME", &root)
        .current_dir(&root)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // O TOML inválido precisa ser reportado com caminho e causa, em pt-BR.
    assert!(
        combined.contains("TOML inválido"),
        "o erro de parsing do TOML global não pode ser silencioso.\n{combined}"
    );
    assert!(
        combined.contains("config.toml"),
        "o erro precisa citar o caminho do arquivo.\n{combined}"
    );
    assert!(
        combined.contains("nenhuma configuração foi sobrescrita"),
        "o erro precisa informar que nada foi sobrescrito.\n{combined}"
    );

    // O arquivo do usuário permanece intacto.
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        broken,
        "o TOML global não pode ser sobrescrito"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_valid_global_toml_is_applied_without_warning() {
    let root = std::env::temp_dir().join(format!(
        "smartsec-valid-global-toml-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let config_dir = root.join("smartsec");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "target_url = \"http://alvo.local\"\nactive_tools = [\"Nmap\"]\n[llm]\nprovider = \"Ollama\"\n",
    )
    .unwrap();

    let output = isolated_command()
        .args(["scan", "--target", "192.0.2.10", "--tools", "Inexistente"])
        .env("XDG_CONFIG_HOME", &root)
        .env("HOME", &root)
        .current_dir(&root)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !format!("{stdout}{stderr}").contains("TOML inválido"),
        "um TOML válido não pode gerar aviso de parsing.\n{stdout}{stderr}"
    );
    std::fs::remove_dir_all(&root).ok();
}
