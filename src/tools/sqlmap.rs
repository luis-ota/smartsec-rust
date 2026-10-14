/// Imagem e versão do SQLMap do manifesto embutido: imagem oficial do Parrot
/// Security, multi-arch e construída em 2026-08-17, fixada por digest para a
/// versão ser auditável no log (RNF09) sem depender de tag mutável.
pub const SQLMAP_IMAGE: &str = "docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596";
/// Versão do SQLMap reportada por `--version` dentro da imagem fixada.
pub const SQLMAP_VERSION: &str = "1.10.4";

/// Respostas fixadas para os prompts do SQLMap, em pares `pergunta=resposta`,
/// casados por *substring* em `lib/core/common.py` (`readInput`), sem ler o TTY.
///
/// `exploit=N` é o item crítico: sem ele o `--batch` responde `Y` a "do you want
/// to exploit this SQL injection?" e enumera o banco alvo; os demais fixam em
/// `N`/`Y`/`C` o que já é default, para a execução ser determinística.
pub const SQLMAP_ANSWERS: &str =
    "exploit=N,keep testing=N,reduce the number of requests=Y,proceed=C";

/// Argumentos do container para varredura de SQL injection sem arquivo e sem
/// shell.
///
/// A imagem declara `ENTRYPOINT ["sqlmap"]` e o executor monta
/// `podman create … IMAGEM <argumentos>`; repetir `sqlmap` como primeiro item é
/// equivalente a não repetir — verificado no container que `sqlmap --version` e
/// `--version` produzem a mesma saída — e o `command_template` exige que o
/// primeiro item seja o executável.
///
/// Cada item é um argumento literal: nenhum shell é usado.
///
/// Origem empírica de cada flag (medida em container, ver
/// `docs/evidence/issue-15-sqlmap.md`):
///
/// - `--batch` é obrigatório: sem ele o SQLMap cai em `_input()` e **trava** no
///   prompt "Do you want to reduce the number of requests? [Y/n]" — medido: 45 s
///   sem término, 3 s com a flag.
/// - `--answers` impede o *takeover*: em `--batch` o default de "do you want to
///   exploit this SQL injection?" é `Y`, e o `Y` inicia a enumeração do banco
///   alvo; `exploit=N` termina a varredura no diagnóstico.
/// - `--disable-coloring` remove os códigos ANSI que o SQLMap emite quando
///   percebe um terminal e que corromperiam o texto lido pelo parser.
/// - `--flush-session` ignora `session.sqlite`: o tmpfs já é efêmero, mas a flag
///   garante que o resultado não dependa de estado reaproveitado caso o
///   `--output-dir` passe a ser um volume.
/// - `--technique=BEUT` limita a agressividade: o default `BEUSTQ` inclui `S`
///   (stacked) e `Q` (inline), que executam statements adicionais no banco do
///   alvo; `BEUT` mantém as técnicas de detecção sem escrita, e medido, sem a
///   flag o log mostra `SQLite > 2.0 stacked queries (heavy query - comment)`.
/// - `--level=2` inclui o valor do parâmetro e a query string; o nível 3 só
///   multiplica requisições com polimento `OR`/`AND` e o nível 1 não testa a
///   query string, justamente onde muitos parâmetros são aceitos.
/// - `--risk=2` é o mínimo que ainda testa *time-based blind*, a técnica que
///   revela injeção cega sem retorno de conteúdo; o risco 3 adiciona consultas
///   pesadas (`heavy query`) contra o banco do alvo.
/// - `--threads=1` combina com o `--cpus 1` do executor: mais threads só
///   disputaria o único CPU e aumentaria a chance de *timeout* na conexão.
/// - `--timeout=10` e `--retries=1` cortam o default `--timeout=30
///   --retries=3`. Medido sem limite: um request consumiu 30 s e o SQLMap
///   imprime `connection timed out to the target URL. sqlmap is going to
///   retry the request(s)`.
/// - `--time-sec=3` é o atraso da detecção *time-based blind*: o default é 5 s,
///   e 3 s basta para o alvo autorizado, local ou de rede próxima, mantendo a
///   técnica viável dentro do timeout do executor.
/// - `--output-dir=/tmp` grava log, sessão e CSV no tmpfs; sem a flag o SQLMap
///   usa `$HOME/.local/share/sqlmap`, somente leitura no executor, e emite
///   `unable to create history directory ... Read-only file system`.
pub fn container_arguments(target: &str) -> Vec<String> {
    vec![
        "sqlmap".to_string(),
        "--batch".to_string(),
        "--answers".to_string(),
        SQLMAP_ANSWERS.to_string(),
        "--disable-coloring".to_string(),
        "--flush-session".to_string(),
        "--technique=BEUT".to_string(),
        "--level=2".to_string(),
        "--risk=2".to_string(),
        "--threads=1".to_string(),
        "--timeout=10".to_string(),
        "--retries=1".to_string(),
        "--time-sec=3".to_string(),
        "--output-dir=/tmp".to_string(),
        "-u".to_string(),
        target.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "http://169.254.1.2:3100/item?id=1";

    #[test]
    fn renders_the_command_validated_empirically_in_the_container() {
        let arguments = container_arguments(TARGET);

        assert_eq!(
            arguments,
            [
                "sqlmap",
                "--batch",
                "--answers",
                "exploit=N,keep testing=N,reduce the number of requests=Y,proceed=C",
                "--disable-coloring",
                "--flush-session",
                "--technique=BEUT",
                "--level=2",
                "--risk=2",
                "--threads=1",
                "--timeout=10",
                "--retries=1",
                "--time-sec=3",
                "--output-dir=/tmp",
                "-u",
                "http://169.254.1.2:3100/item?id=1",
            ]
        );
    }

    #[test]
    fn command_never_introduces_a_shell_metacharacter() {
        let arguments = container_arguments("http://alvo.local:8080/item?id=1");

        for argument in &arguments {
            assert!(!argument.contains('|'), "{argument}");
            assert!(!argument.contains('>'), "{argument}");
            assert!(!argument.contains('<'), "{argument}");
            assert!(!argument.contains(';'), "{argument}");
            assert!(!argument.contains('$'), "{argument}");
            assert!(!argument.contains('&'), "{argument}");
            assert!(!argument.contains('`'), "{argument}");
        }
    }

    #[test]
    fn every_aggressiveness_limit_is_present_and_justified() {
        let arguments = container_arguments(TARGET);

        // Não interativo: sem estas duas flags o SQLMap trava ou ataca o banco.
        assert!(arguments.iter().any(|argument| argument == "--batch"));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--answers", SQLMAP_ANSWERS]));
        // `--answers` precisa responder `N` à pergunta de exploração.
        assert!(SQLMAP_ANSWERS.starts_with("exploit=N"), "{SQLMAP_ANSWERS}");

        // Técnicas destrutivas (stacked `S` e inline `Q`) ficam de fora.
        let technique = arguments
            .iter()
            .find(|argument| argument.starts_with("--technique="))
            .expect("a lista de técnicas deve ser explícita");
        assert_eq!(technique, "--technique=BEUT");
        assert!(!technique.contains('S'), "{technique}");
        assert!(!technique.contains('Q'), "{technique}");

        // Demais limites de carga e de tempo.
        for limit in [
            "--level=2",
            "--risk=2",
            "--threads=1",
            "--timeout=10",
            "--retries=1",
            "--time-sec=3",
            "--disable-coloring",
            "--flush-session",
            "--output-dir=/tmp",
        ] {
            assert!(
                arguments.iter().any(|argument| argument == limit),
                "{limit}"
            );
        }
    }

    #[test]
    fn the_target_is_the_only_value_carried_into_the_command() {
        let arguments = container_arguments(TARGET);

        // O alvo entra como item literal de `-u`, sem virar flag.
        let position = arguments
            .iter()
            .position(|argument| argument == "-u")
            .expect("o alvo deve ser informado com -u");
        assert_eq!(arguments[position + 1], TARGET);
        assert_eq!(arguments.iter().filter(|item| *item == TARGET).count(), 1);
    }

    #[test]
    fn pins_the_image_by_digest_and_registers_the_version() {
        assert!(SQLMAP_IMAGE.contains("@sha256:"));
        assert_eq!(SQLMAP_VERSION, "1.10.4");
    }
}
