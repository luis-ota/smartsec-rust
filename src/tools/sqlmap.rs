/// Imagem e versão do SQLMap usadas pelo manifesto embutido.
///
/// A imagem é fixada por digest para que a versão do scanner seja auditável no
/// log estruturado (RNF09) e não dependa de uma tag mutável. É a imagem
/// oficial do Parrot Security Project, com tag versionada, multi-arch e
/// construída em 2026-08-17.
pub const SQLMAP_IMAGE: &str = "docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596";
/// Versão do SQLMap reportada por `--version` dentro da imagem fixada.
pub const SQLMAP_VERSION: &str = "1.10.4";

/// Respostas fixadas para os prompts do SQLMap, em pares `pergunta=resposta`.
///
/// A origem é `lib/core/common.py` (`readInput`), que casa cada chave como
/// *substring* do texto da pergunta e devolve o valor sem ler o terminal.
///
/// `exploit=N` é o item crítico e o motivo de `--answers` existir no comando.
/// Sem ele o SQLMap, em modo `--batch`, responde `Y` a "do you want to exploit
/// this SQL injection?" e sai do escopo da varredura para enumerar banco,
/// tabelas e colunas do alvo. Os demais fixam em `N`/`Y`/`C` o que já é o
/// default do `--batch`, para que a execução seja determinística mesmo se o
/// default mudar em outra versão da imagem.
pub const SQLMAP_ANSWERS: &str =
    "exploit=N,keep testing=N,reduce the number of requests=Y,proceed=C";

/// Argumentos do container para varredura de SQL injection sem arquivo e sem
/// shell.
///
/// A imagem declara `ENTRYPOINT ["sqlmap"]`, e o executor monta
/// `podman create … IMAGEM <argumentos>`. Repetir `sqlmap` como primeiro item
/// deixa o comando explícito e equivalente ao que a issue descreve; verificado
/// no container que `sqlmap --version` e `--version` produzem a mesma saída.
///
/// Cada item é um argumento literal: nenhum shell é usado.
///
/// Origem empírica de cada flag (medida em container, ver
/// `docs/evidence/issue-15-sqlmap.md`):
///
/// - `--batch` é obrigatório. Sem ele o SQLMap cai em `_input()` e **trava**
///   indefinidamente esperando o prompt "Do you want to reduce the number of
///   requests? [Y/n]" — medido: 45 s sem término, 3 s com a flag. Sem
///   `--batch` a leitura só não bloqueia por acidente, quando o stdin não é
///   um TTY e o scanner adivinha o default; `--batch` é a garantia.
/// - `--answers` impede o *takeover*. Em `--batch` o default de "do you want
///   to exploit this SQL injection?" é `Y`, e o `Y` inicia a enumeração do
///   banco alvo. Com `exploit=N` a pergunta é respondida com `N` e a varredura
///   termina no diagnóstico.
/// - `--disable-coloring` remove os códigos ANSI que o SQLMap emite quando
///   perceives um terminal, e que corromperiam o texto lido pelo parser.
/// - `--flush-session` ignora `session.sqlite`. O tmpfs do container já é
///   efêmero, mas a flag garante que o resultado não dependa de estado
///   reaproveitado caso o `--output-dir` passe a ser um volume.
/// - `--technique=BEUT` limita a agressividade. O default do SQLMap é `BEUSTQ`
///   e inclui `S` (stacked queries) e `Q` (inline queries), que executam
///   statements adicionais no banco do alvo. Manter `B`, `E`, `U` e `T`
///   preserva as quatro técnicas de detecção (boolean-based, error-based,
///   UNION e time-based) sem escrita no banco. Na execução real sem esta flag
///   o log mostra `SQLite > 2.0 stacked queries (heavy query - comment)` e
///   `SQLite > 2.0 stacked queries (heavy query)`, ausentes com ela.
/// - `--level=2` inclui o valor do parâmetro e a query string. O nível 3 adiciona
///   polimento de payload `OR`/`AND`, multiplicando as requisições sem
///   encontrar injeção que o nível 2 não encontra. O nível 1 não testa a query
///   string, justamente onde muitos parâmetros são aceitos.
/// - `--risk=2` é o mínimo que ainda testa *time-based blind*, a técnica que
///   revela injeção cega sem retorno de conteúdo. O risco 3 adiciona consultas pesadas
///   (`heavy query`) e mais requisições contra o banco do alvo.
/// - `--threads=1` combina com o `--cpus 1` do executor: mais threads só
///   disputa o único CPU e aumenta a chance de *timeout* na conexão.
/// - `--timeout=10` e `--retries=1` cortam o default `--timeout=30
///   --retries=3`. Medido sem limite: um request consumiu 30 s e o SQLMap
///   imprime `connection timed out to the target URL. sqlmap is going to
///   retry the request(s)`.
/// - `--time-sec=3` é o atraso usado na detecção *time-based blind*. O default
///   é 5 s; 3 s basta para o alvo autorizado, local ou de rede próxima, e
///   mantém a técnica viável dentro do timeout do executor.
/// - `--output-dir=/tmp` grava log, sessão e CSV no tmpfs. Sem a flag o SQLMap
///   usa `$HOME/.local/share/sqlmap`, que é somente leitura no executor e faz
///   o scanner emitir `unable to create history directory ... Read-only file
///   system`.
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
