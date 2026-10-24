//! Subcomando `smartsec auth`: cadastro, consulta e remoção da chave da API.
//!
//! A chave fica em um arquivo privado 0600 (`auth.json`), como OpenCode/Codex.
//! Ela não é aceita como argumento, não é gravada no TOML e nunca é impressa
//! inteira. O keyring do sistema não é requisito.

use crate::config::persistence::{
    self, ApiKeyStatus, CredentialStore, CredentialStoreError, SystemCredentialStore,
};
use anyhow::{bail, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{self, IsTerminal, Read, Write};

pub const AUTH_EXIT_OK: i32 = 0;
pub const AUTH_EXIT_MISSING: i32 = 1;
pub const AUTH_EXIT_ERROR: i32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthAction {
    Set { from_stdin: bool, to_file: bool },
    Status,
    Remove,
    Help,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthArgs {
    pub action: AuthAction,
}

impl AuthArgs {
    pub fn parse(arguments: &[String]) -> Result<Self> {
        let Some(command) = arguments.first() else {
            return Ok(Self {
                action: AuthAction::Help,
            });
        };
        if matches!(command.as_str(), "--help" | "-h") {
            if arguments.len() > 1 {
                bail!("`smartsec auth --help` não aceita outros argumentos");
            }
            return Ok(Self {
                action: AuthAction::Help,
            });
        }
        let action = match command.as_str() {
            "set" => {
                let mut from_stdin = false;
                let mut to_file = false;
                for argument in &arguments[1..] {
                    match argument.as_str() {
                        "--stdin" if !from_stdin => from_stdin = true,
                        "--stdin" => bail!("`--stdin` foi informado mais de uma vez"),
                        "--file" if !to_file => to_file = true,
                        "--file" => bail!("`--file` foi informado mais de uma vez"),
                        "--help" | "-h" => {
                            return Ok(Self {
                                action: AuthAction::Help,
                            });
                        }
                        _ => bail!(
                            "`smartsec auth set` não aceita esse argumento; a chave não pode ser passada pela linha de comando. Use `smartsec auth set` (digitação oculta) ou `smartsec auth set --stdin` (CI). `--file` é aceito por compatibilidade."
                        ),
                    }
                }
                AuthAction::Set {
                    from_stdin,
                    to_file,
                }
            }
            "status" | "remove" => {
                if let Some(argument) = arguments.get(1) {
                    if matches!(argument.as_str(), "--help" | "-h") {
                        return Ok(Self {
                            action: AuthAction::Help,
                        });
                    }
                    bail!(
                        "`smartsec auth {command}` não aceita opções; use `smartsec auth --help` para ver o contrato."
                    );
                }
                if command == "status" {
                    AuthAction::Status
                } else {
                    AuthAction::Remove
                }
            }
            _ => bail!(
                "subcomando de auth desconhecido; use `smartsec auth set`, `smartsec auth status` ou `smartsec auth remove`."
            ),
        };
        Ok(Self { action })
    }
}

pub fn print_help() {
    println!("SmartSec — Chave da API (arquivo privado 0600)");
    println!();
    println!("Uso:");
    println!("  smartsec auth set [--stdin]  Lê a chave sem eco e grava em ~/.config/smartsec/auth.json (0600)");
    println!("  smartsec auth status         Mostra se há chave, provedor, modelo e final");
    println!("  smartsec auth remove         Remove a chave do arquivo local");
    println!("  smartsec auth --help         Mostra esta ajuda");
    println!();
    println!("A chave nunca é gravada no TOML, não passa por argumentos de processo");
    println!("e não aparece em logs. Sem `--stdin`, a digitação é oculta no terminal.");
    println!("O armazenamento é um JSON privado (0600), como OpenCode/Codex/Claude Code;");
    println!("não depende de keyring nem de prompt gráfico. Com `--stdin`:");
    println!("  smartsec auth set --stdin < /run/secrets/smartsec-api-key");
    println!();
    println!("SMARTSEC_API_KEY é um override explícito de sessão/CI: tem precedência");
    println!("sobre o arquivo, não é gravada e não substitui `auth set`.");
}

pub fn run(args: AuthArgs) -> Result<i32> {
    match args.action {
        AuthAction::Help => {
            print_help();
            Ok(AUTH_EXIT_OK)
        }
        AuthAction::Set {
            from_stdin,
            to_file: _,
        } => {
            let key = if from_stdin {
                read_stdin_key()?
            } else {
                read_hidden_key()?
            };
            let key = normalize_key(&key)?;
            run_set(&SystemCredentialStore, &key)?;
            println!(
                "Chave da API gravada em {} (0600).",
                persistence::api_key_file_path().display()
            );
            println!("Ela não foi gravada no TOML. Confira com: smartsec auth status");
            warn_about_env_override();
            Ok(AUTH_EXIT_OK)
        }
        AuthAction::Status => {
            let mut stdout = io::stdout().lock();
            let env_override = env_key_present();
            let code = run_status(
                &SystemCredentialStore,
                &configured_llm(),
                env_override,
                &mut stdout,
            )?;
            stdout.flush()?;
            drop(stdout);
            if !env_override && persistence::api_key_file_exists() {
                println!(
                    "  fonte:    arquivo local 0600 ({})",
                    persistence::api_key_file_path().display()
                );
            }
            Ok(code)
        }
        AuthAction::Remove => {
            run_remove(&SystemCredentialStore)?;
            println!("Chave da API removida do arquivo local.");
            warn_about_env_override();
            Ok(AUTH_EXIT_OK)
        }
    }
}

pub fn run_set(store: &dyn CredentialStore, raw_key: &str) -> Result<()> {
    let key = normalize_key(raw_key)?;
    store
        .save(&key)
        .map_err(|error| actionable_error("set", error))
}

pub fn run_remove(store: &dyn CredentialStore) -> Result<()> {
    match store.delete() {
        Ok(()) | Err(CredentialStoreError::Missing) => Ok(()),
        Err(error) => Err(actionable_error("remove", error)),
    }
}

pub fn run_status(
    store: &dyn CredentialStore,
    llm: &LlmConfiguration,
    env_override: bool,
    out: &mut dyn Write,
) -> Result<i32> {
    writeln!(out, "SmartSec — Chave da API")?;
    writeln!(out)?;
    match llm {
        LlmConfiguration::Configured { provider, model } => {
            writeln!(out, "  Provedor: {provider}")?;
            writeln!(out, "  Modelo:   {model}")?;
        }
        LlmConfiguration::NotConfigured { provider } => {
            writeln!(out, "  Provedor: {provider} (não configurado)")?;
            writeln!(out, "  Modelo:   (não configurado)")?;
            writeln!(out, "            configure com: smartsec onboarding")?;
        }
        LlmConfiguration::Unreadable { reason } => {
            writeln!(out, "  Provedor: não foi possível ler a configuração")?;
            writeln!(out, "            {reason}")?;
        }
    }

    let status = store.status();
    match &status {
        ApiKeyStatus::Available(key) => {
            writeln!(out, "  Chave:    cadastrada")?;
            writeln!(
                out,
                "            {} caracteres · final {}",
                key.chars().count(),
                mask_key(key)
            )?;
        }
        ApiKeyStatus::Missing => {
            writeln!(out, "  Chave:    não cadastrada")?;
            writeln!(out, "            cadastre com: smartsec auth set")?;
        }
        ApiKeyStatus::Locked(reason) => {
            writeln!(out, "  Chave:    indisponível — {reason}")?;
            writeln!(
                out,
                "            desbloqueie o cofre do sistema e execute `smartsec auth status` de novo"
            )?;
        }
        ApiKeyStatus::Unavailable(reason) => {
            writeln!(out, "  Chave:    indisponível — {reason}")?;
            writeln!(
                out,
                "            verifique as permissões de ~/.config/smartsec/auth.json e execute `smartsec auth status` de novo"
            )?;
        }
    }

    if env_override {
        writeln!(out)?;
        writeln!(
            out,
            "  Sessão:   SMARTSEC_API_KEY definida (override temporário; não é gravada)"
        )?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "  O armazenamento é ~/.config/smartsec/auth.json (0600); a chave nunca vai para o TOML."
    )?;
    Ok(status_exit_code(&status, env_override))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmConfiguration {
    Configured { provider: String, model: String },
    NotConfigured { provider: String },
    Unreadable { reason: String },
}

pub fn configured_llm() -> LlmConfiguration {
    match persistence::try_load_config_file() {
        Ok(config) => summarize_llm(&config),
        Err(_) => LlmConfiguration::Unreadable {
            reason: "o TOML de configuração não pôde ser lido; verifique o arquivo ou execute `smartsec onboarding`".to_string(),
        },
    }
}

fn summarize_llm(config: &persistence::PersistedConfig) -> LlmConfiguration {
    let provider = config.llm.provider;
    let base_url = if config.llm.base_url.trim().is_empty() {
        provider.default_base_url()
    } else {
        config.llm.base_url.as_str()
    };
    if base_url.trim().is_empty() {
        return LlmConfiguration::NotConfigured {
            provider: provider.label().to_string(),
        };
    }
    let model = if config.llm.model.trim().is_empty() {
        provider.default_model().to_string()
    } else {
        config.llm.model.clone()
    };
    LlmConfiguration::Configured {
        provider: provider.label().to_string(),
        model,
    }
}

fn status_exit_code(status: &ApiKeyStatus, env_override: bool) -> i32 {
    if env_override || matches!(status, ApiKeyStatus::Available(_)) {
        AUTH_EXIT_OK
    } else if matches!(status, ApiKeyStatus::Missing) {
        AUTH_EXIT_MISSING
    } else {
        AUTH_EXIT_ERROR
    }
}

/// Mostra apenas o tamanho e o final da chave. Chaves com até quatro
/// caracteres ficam inteiramente ocultas, para que o status nunca as revele.
pub fn mask_key(key: &str) -> String {
    let length = key.chars().count();
    if length == 0 {
        return String::new();
    }
    if length <= 12 {
        return "•".repeat(length);
    }
    let suffix: String = key.chars().skip(length - 4).collect();
    format!("••••{suffix}")
}

fn normalize_key(raw: &str) -> Result<String> {
    let key = raw.trim();
    if key.is_empty() {
        bail!("a chave da API não pode estar vazia; nada foi gravado");
    }
    if key.chars().any(char::is_control) {
        bail!(
            "a chave da API não pode conter quebras de linha ou caracteres de controle; nada foi gravado"
        );
    }
    Ok(key.to_string())
}

fn actionable_error(action: &str, error: CredentialStoreError) -> anyhow::Error {
    match error {
        CredentialStoreError::Locked(reason) => anyhow::anyhow!(
            "{reason}. Desbloqueie o cofre de segredos do sistema (por exemplo, gnome-keyring ou KWallet) e execute `smartsec auth {action}` de novo. Em SSH/TTY sem prompt gráfico, use `smartsec auth set --file` ou SMARTSEC_API_KEY."
        ),
        CredentialStoreError::Unavailable(reason) => anyhow::anyhow!(
            "{reason}. Verifique as permissões de ~/.config/smartsec/auth.json e execute `smartsec auth {action}` de novo."
        ),
        CredentialStoreError::Missing => anyhow::anyhow!(
            "nenhuma chave da API está cadastrada; cadastre com `smartsec auth set`."
        ),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn ensure_store_available(store: &dyn CredentialStore, action: &str) -> Result<()> {
    match store.status() {
        ApiKeyStatus::Locked(reason) => Err(actionable_error(
            action,
            CredentialStoreError::Locked(reason),
        )),
        ApiKeyStatus::Unavailable(reason) => Err(actionable_error(
            action,
            CredentialStoreError::Unavailable(reason),
        )),
        _ => Ok(()),
    }
}

fn env_key_present() -> bool {
    std::env::var("SMARTSEC_API_KEY").is_ok_and(|value| !value.trim().is_empty())
}

fn warn_about_env_override() {
    if env_key_present() {
        println!(
            "Atenção: SMARTSEC_API_KEY está definida e tem precedência nesta sessão; o arquivo local só será usado quando a variável não estiver definida."
        );
    }
}

fn read_stdin_key() -> Result<String> {
    if io::stdin().is_terminal() {
        bail!(
            "`smartsec auth set --stdin` é para CI e entrada redirecionada; no terminal, use `smartsec auth set` para ocultar a digitação"
        );
    }
    const MAX_KEY_BYTES: u64 = 4 * 1024;
    let mut raw = String::new();
    io::stdin()
        .lock()
        .take(MAX_KEY_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| {
            anyhow::anyhow!("não foi possível ler a chave da entrada padrão: {error}")
        })?;
    if raw.len() as u64 > MAX_KEY_BYTES {
        bail!("a chave da API excede o limite de 4 KiB; nada foi gravado");
    }
    Ok(raw)
}

fn read_hidden_key() -> Result<String> {
    if !io::stdin().is_terminal() {
        bail!(
            "a leitura interativa exige um terminal; use `smartsec auth set --stdin` para ler a chave da entrada padrão"
        );
    }
    // A entrada crua é habilitada antes do prompt: se o operador começar a
    // digitar imediatamente, o terminal já está sem eco.
    let result = {
        let _guard = RawModeGuard::enable().map_err(|error| {
            anyhow::anyhow!(
                "não foi possível preparar o terminal para a leitura oculta: {error}; use `smartsec auth set --stdin`"
            )
        })?;
        eprint!("Digite a chave da API (a entrada não será exibida): ");
        io::stderr().flush()?;
        read_key_events()
    };
    eprintln!();
    result
}

fn read_key_events() -> Result<String> {
    let mut key = String::new();
    loop {
        if let Event::Key(key_event) = event::read()? {
            if key_event.kind == KeyEventKind::Release {
                continue;
            }
            match key_event.code {
                KeyCode::Enter => return Ok(key),
                KeyCode::Esc => bail!("entrada cancelada; nenhuma chave foi gravada"),
                KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                    bail!("entrada cancelada; nenhuma chave foi gravada")
                }
                KeyCode::Char('d') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                    bail!("entrada cancelada; nenhuma chave foi gravada")
                }
                KeyCode::Backspace => {
                    key.pop();
                }
                KeyCode::Char(character)
                    if !key_event.modifiers.contains(KeyModifiers::CONTROL)
                        && !key_event.modifiers.contains(KeyModifiers::ALT) =>
                {
                    key.push(character);
                }
                _ => {}
            }
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::llm_config::LlmProviderKind;
    use crate::config::persistence::{InMemoryCredentialStore, PersistedConfig};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn configured() -> LlmConfiguration {
        LlmConfiguration::Configured {
            provider: "OpenAI".to_string(),
            model: "gpt-4o".to_string(),
        }
    }

    #[test]
    fn parses_every_auth_action() {
        let cases = [
            (args(&[]), AuthAction::Help),
            (args(&["--help"]), AuthAction::Help),
            (
                args(&["set"]),
                AuthAction::Set {
                    from_stdin: false,
                    to_file: false,
                },
            ),
            (
                args(&["set", "--stdin"]),
                AuthAction::Set {
                    from_stdin: true,
                    to_file: false,
                },
            ),
            (args(&["status"]), AuthAction::Status),
            (args(&["remove"]), AuthAction::Remove),
        ];
        for (arguments, expected) in cases {
            assert_eq!(
                AuthArgs::parse(&arguments).unwrap().action,
                expected,
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_auth_usage() {
        assert!(AuthArgs::parse(&args(&["importar"])).is_err());
        assert!(AuthArgs::parse(&args(&["status", "--stdin"])).is_err());
        assert!(AuthArgs::parse(&args(&["remove", "agora"])).is_err());
        assert!(AuthArgs::parse(&args(&["set", "--stdin", "--stdin"])).is_err());
        assert!(AuthArgs::parse(&args(&["--help", "set"])).is_err());
    }

    #[test]
    fn never_echoes_a_key_passed_by_mistake_as_an_argument() {
        let secret = "sk-segredo-que-nao-pode-vazar";
        let error = AuthArgs::parse(&args(&["set", secret]))
            .unwrap_err()
            .to_string();

        assert!(!error.contains(secret), "{error}");
        assert!(error.contains("linha de comando"), "{error}");
        assert!(error.contains("--stdin"), "{error}");
    }

    #[test]
    fn set_status_and_remove_use_the_injected_store() {
        let store = InMemoryCredentialStore::new();

        run_set(&store, "  sk-teste-1234\n").expect("a chave deve ser gravada");
        assert_eq!(store.stored_key().as_deref(), Some("sk-teste-1234"));

        let mut output = Vec::new();
        let code = run_status(&store, &configured(), false, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(code, AUTH_EXIT_OK);
        assert!(text.contains("OpenAI"), "{text}");
        assert!(text.contains("gpt-4o"), "{text}");
        assert!(text.contains("13 caracteres"), "{text}");
        assert!(text.contains("••••1234"), "{text}");
        assert!(!text.contains("sk-teste-1234"), "{text}");

        run_remove(&store).expect("a chave deve ser removida");
        assert!(store.stored_key().is_none());

        let mut output = Vec::new();
        let code = run_status(&store, &configured(), false, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(code, AUTH_EXIT_MISSING);
        assert!(text.contains("smartsec auth set"), "{text}");
    }

    #[test]
    fn status_does_not_reveal_short_keys() {
        let store = InMemoryCredentialStore::new();
        run_set(&store, "abcd").expect("a chave deve ser gravada");

        let mut output = Vec::new();
        run_status(&store, &configured(), false, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(!text.contains("abcd"), "{text}");
        assert!(text.contains("4 caracteres"), "{text}");
        assert_eq!(mask_key("abcd"), "••••");
        assert_eq!(mask_key("abcde"), "•••••");
        assert_eq!(mask_key("chave-de-teste"), "••••este");
    }

    #[test]
    fn locked_keyring_is_actionable_on_every_action() {
        let store = InMemoryCredentialStore::with_failure(CredentialStoreError::Locked(
            "o cofre de segredos do sistema está bloqueado".to_string(),
        ));

        let set_error = run_set(&store, "chave-de-teste").unwrap_err().to_string();
        assert!(set_error.contains("Desbloqueie o cofre"), "{set_error}");
        assert!(set_error.contains("auth set"), "{set_error}");

        let preflight = ensure_store_available(&store, "set")
            .unwrap_err()
            .to_string();
        assert!(preflight.contains("Desbloqueie o cofre"), "{preflight}");

        let remove_error = run_remove(&store).unwrap_err().to_string();
        assert!(
            remove_error.contains("Desbloqueie o cofre"),
            "{remove_error}"
        );

        let mut output = Vec::new();
        let code = run_status(&store, &configured(), false, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(code, AUTH_EXIT_ERROR);
        assert!(text.contains("desbloqueie o cofre"), "{text}");
    }

    #[test]
    fn environment_override_is_reported_and_counts_as_a_usable_key() {
        let store = InMemoryCredentialStore::new();

        let mut output = Vec::new();
        let code = run_status(&store, &configured(), true, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, AUTH_EXIT_OK);
        assert!(text.contains("SMARTSEC_API_KEY"), "{text}");
        assert!(text.contains("não é gravada"), "{text}");
    }

    #[test]
    fn unreadable_configuration_does_not_hide_the_credential_status() {
        let store = InMemoryCredentialStore::new();
        run_set(&store, "chave-de-teste").expect("a chave deve ser gravada");

        let mut output = Vec::new();
        let code = run_status(
            &store,
            &LlmConfiguration::Unreadable {
                reason: "TOML inválido".to_string(),
            },
            false,
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, AUTH_EXIT_OK);
        assert!(text.contains("TOML inválido"), "{text}");
        assert!(text.contains("cadastrada"), "{text}");
    }

    #[test]
    fn summarizes_the_configured_provider_and_model() {
        let mut config = PersistedConfig::default();
        assert_eq!(
            summarize_llm(&config),
            LlmConfiguration::NotConfigured {
                provider: "Personalizado".to_string()
            }
        );

        config.llm.provider = LlmProviderKind::OpenAI;
        assert_eq!(
            summarize_llm(&config),
            LlmConfiguration::Configured {
                provider: "OpenAI".to_string(),
                model: "gpt-4o".to_string(),
            }
        );

        config.llm.model = "gpt-4o-mini".to_string();
        assert_eq!(
            summarize_llm(&config),
            LlmConfiguration::Configured {
                provider: "OpenAI".to_string(),
                model: "gpt-4o-mini".to_string(),
            }
        );
    }

    #[test]
    fn normalizes_stdin_and_rejects_empty_or_multiline_keys() {
        assert_eq!(normalize_key("  chave-1234\n").unwrap(), "chave-1234");
        for invalid in ["", "   \n", "chave\noutra"] {
            let error = normalize_key(invalid).unwrap_err().to_string();
            assert!(!error.contains("chave\noutra"), "{error}");
            assert!(error.contains("nada foi gravado"), "{error}");
        }
    }
}
