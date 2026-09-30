/// Imagem e versão do TruffleHog usadas pelo manifesto embutido.
///
/// A imagem é fixada por digest para que a versão do scanner seja auditável no
/// log estruturado (RNF09) e não dependa de uma tag mutável. O digest é
/// multi-arch: a mesma referência resolve localmente sem pull e reporta a
/// versão declarada em `TRUFFLEHOG_VERSION`.
///
/// Origem empírica de todos os valores deste arquivo:
/// `docs/evidence/issue-18-trufflehog.md`.
pub const TRUFFLEHOG_IMAGE: &str = "docker.io/trufflesecurity/trufflehog@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db";
/// Versão do TruffleHog reportada por `--version` dentro da imagem fixada.
pub const TRUFFLEHOG_VERSION: &str = "3.97.9";

/// Ponto de montagem do repositório dentro do container.
///
/// O repositório analisado entra **somente leitura** (`TCC_SPEC.md` §7: "os
/// templates sao montados em modo somente leitura"), pela mesma razão pela
/// qual os templates do Nuclei são montados: o scanner precisa ler um diretório
/// do host, e o executor sempre acrescenta a sufixo `:ro` ao volume. O
/// TruffleHog só precisa de leitura, então o ganho de escrita seria zero.
pub const REPOSITORY_MOUNT_PATH: &str = "/alvo";

/// Prefixo do esquema que identifica um repositório remoto autorizado.
///
/// O `git` do TruffleHog aceita `https://`, `http://`, `ssh://` e `file://`.
/// O SmartSec só encaminha os dois primeiros, porque são os únicos que a
/// validação de alvo da configuração aceita.
pub const REMOTE_URI_PREFIXES: &[&str] = &["https://", "http://"];

/// Argumentos do container para a varredura de um repositório.
///
/// A imagem declara `ENTRYPOINT ["trufflehog"]`, e o executor monta
/// `podman create … IMAGEM <argumentos>`. Cada item é um argumento literal:
/// nenhum shell é usado.
///
/// `container_repo_path` é o ponto de montagem do repositório local. Quando
/// não está vazio, o alvo vira `file://<mount>` e nenhum caminho do host
/// atravessa o comando. Quando está vazio, `target` é um repositório remoto já
/// autorizado e é repassado como URI.
///
/// O subcomando `git` abre a lista porque o `command_template` do manifesto
/// exige que o primeiro item seja o executável e não comece com `-`. Repetir
/// `trufflehog` como primeiro item **não** funciona: o CLIKING do TruffleHog
/// rejeita com `expected command but got "trufflehog"` e exit 1, medido. As
/// flags globais são aceitas normalmente depois do subcomando, então a ordem
/// não altera o resultado.
///
/// Cada flag existe por um motivo medido em container real, não por hábito:
///
/// - `--json` **obrigatório**. Sem ele o TruffleHog imprime o valor completo
///   do segredo em texto legível no stdout (`Found unverified result …
///   Raw result: -----BEGIN RSA PRIVATE KEY----- …`). É o modo que torna a
///   integração possível, e o `--json` sozinho não resolve a exposição: os
///   campos `Raw`, `RawV2` e `SecretParts` continuam carregando o segredo
///   inteiro, e o parser os descarta por allow-list.
/// - `--no-update` **obrigatório**. Sem ele o auto-updater tenta gravar o
///   binário novo sob o `--read-only` do executor, falha com
///   `cannot move binary (exit status 1)` e **aborta a varredura inteira**
///   com exit 1 e stdout vazio. O SmartSec reportaria "nenhum segredo
///   encontrado" para uma varredura que sequer executou.
/// - `--fail-on-scan-errors` **obrigatório**. Sem ele, um alvo inexistente
///   termina com exit 0 e stdout vazio, e o `lstat … no such file or
///   directory` fica só no stderr: o scanner não autorizaria o alvo
///   silenciosamente como varredura limpa.
/// - `--no-verification` desliga a verificação remota. A verificação sai pela
///   rede para o endpoint do provedor de cada detector **enviando o segredo
///   detectado**, e degrada em silêncio quando a rede não responde: medido,
///   3,58 s e 3 tentativas a mais, com o achado rebaixado para `unverified`
///   e nenhum erro reportado. Desligada por padrão, a decisão está registrada
///   para review.
/// - `--no-color` evita sequências ANSI no JSONL. O executor não aloca TTY, e
///   a cor poluiria a evidência parsada sem acrescentar informação.
///
/// Não há flag de limitação de profundidade (`--max-depth`, `--since-commit`):
/// as duas foram medidas e **suprimem achados reais** de forma reprodutível
/// (`--max-depth=1` e `2` sobre um repositório de 2 commits apagam o segredo
/// encontrado). O escopo é limitado pelo alvo explícito do usuário e pelo
/// mount somente leitura, não por essas flags.
pub fn container_arguments(target: &str, container_repo_path: &str) -> Vec<String> {
    let source = if container_repo_path.is_empty() {
        target.to_string()
    } else {
        format!("file://{container_repo_path}")
    };
    vec![
        "git".to_string(),
        "--no-update".to_string(),
        "--no-color".to_string(),
        "--json".to_string(),
        "--no-verification".to_string(),
        "--fail-on-scan-errors".to_string(),
        source,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNT: &str = "/alvo";

    #[test]
    fn renders_jsonl_to_stdout_with_a_read_only_repository_mount() {
        let arguments = container_arguments("/home/dev/repo", MOUNT);

        assert_eq!(
            arguments,
            [
                "git",
                "--no-update",
                "--no-color",
                "--json",
                "--no-verification",
                "--fail-on-scan-errors",
                "file:///alvo"
            ]
        );
    }

    #[test]
    fn a_remote_authorized_repository_is_passed_as_uri_without_a_mount() {
        let arguments = container_arguments("https://github.com/org/repo.git", "");

        assert_eq!(
            arguments.last().map(String::as_str),
            Some("https://github.com/org/repo.git")
        );
        // Nenhum caminho do host pode aparecer quando o alvo é remoto.
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("/home/") || argument.contains("file://")),
            "{arguments:?}"
        );
    }

    #[test]
    fn never_asks_for_a_read_write_mount_or_a_shell_metacharacter() {
        for arguments in [
            container_arguments("/home/dev/repo", MOUNT),
            container_arguments("https://github.com/org/repo.git", ""),
        ] {
            for argument in &arguments {
                assert!(!argument.contains('|'), "{argument}");
                assert!(!argument.contains('>'), "{argument}");
                assert!(!argument.contains('<'), "{argument}");
                assert!(!argument.contains(';'), "{argument}");
                assert!(!argument.contains('$'), "{argument}");
                assert!(!argument.contains('&'), "{argument}");
                assert!(!argument.contains('`'), "{argument}");
            }
            // O repositório analisado é montado somente pelo executor, em `:ro`.
            assert!(
                !arguments.iter().any(|argument| argument.ends_with(":rw")),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn the_host_path_never_reaches_the_command_of_a_local_repository() {
        let arguments = container_arguments("/home/dev/segredos/repo", MOUNT);

        // Só o ponto de montagem fixo atravessa o comando; o caminho do host
        // viaja pelo `--volume` do executor.
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("segredos")),
            "{arguments:?}"
        );
    }

    #[test]
    fn keeps_the_flags_that_make_the_scan_reproducible_and_auditable() {
        let arguments = container_arguments("/home/dev/repo", MOUNT);

        // `--json` evita o segredo em claro; `--no-update` evita a varredura
        // abortada sob `--read-only`; `--fail-on-scan-errors` evita a varredura
        // limpa com alvo inexistente.
        assert!(arguments.contains(&"--json".to_string()));
        assert!(arguments.contains(&"--no-update".to_string()));
        assert!(arguments.contains(&"--fail-on-scan-errors".to_string()));
        // A verificação remota do segredo fica desligada por padrão.
        assert!(arguments.contains(&"--no-verification".to_string()));
        // Nenhuma flag de limitação de profundidade suprime achados reais.
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("--max-depth")),
            "{arguments:?}"
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("--since-commit")),
            "{arguments:?}"
        );
        // `--fail` transformaria "achou segredo" em falha de execução.
        assert!(!arguments.contains(&"--fail".to_string()));
    }

    #[test]
    fn pins_the_image_by_digest_and_registers_the_version() {
        assert!(TRUFFLEHOG_IMAGE.contains("@sha256:"));
        assert_eq!(
            TRUFFLEHOG_VERSION, "3.97.9",
            "a versão deve corresponder ao `trufflehog --version` da imagem fixada"
        );
    }

    #[test]
    fn recognizes_only_the_remote_schemes_accepted_by_target_validation() {
        for target in ["https://github.com/org/repo.git", "http://git.interno/repo"] {
            assert!(
                REMOTE_URI_PREFIXES
                    .iter()
                    .any(|prefix| target.starts_with(prefix)),
                "{target}"
            );
        }
        // `ssh://` e `file://` não passam pela validação de alvo da CLI, e
        // `git@host:org/repo` (scp-like) também não: não são offered aqui.
        for target in ["ssh://git@host/repo.git", "file:///alvo", "/home/dev/repo"] {
            assert!(
                !REMOTE_URI_PREFIXES
                    .iter()
                    .any(|prefix| target.starts_with(prefix)),
                "{target}"
            );
        }
    }
}
