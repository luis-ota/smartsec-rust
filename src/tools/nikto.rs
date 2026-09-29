/// Imagem e versão do Nikto usadas pelo manifesto embutido.
///
/// A imagem é fixada por digest para que a versão do scanner seja auditável no
/// log estruturado (RNF09) e não dependa de uma tag mutável.
pub const NIKTO_IMAGE: &str = "docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b";
/// Versão do Nikto reportada por `-Version` dentro da imagem fixada.
pub const NIKTO_VERSION: &str = "2.1.6";

/// Argumentos do container para varredura estruturada em JSON no stdout.
///
/// A imagem declara `ENTRYPOINT ["nikto.pl"]`, e o executor monta
/// `podman create … IMAGEM <argumentos>`. O executável é repetido como primeiro
/// item para deixar o comando explícito e equivalente ao que a issue descreve;
/// o Nikto ignora o token e a saída é idêntica à execução sem ele.
///
/// Cada item é um argumento literal: nenhum shell é usado.
///
/// - `-o -` faz o Nikto escrever o relatório JSON no stdout em vez de criar
///   arquivo. Sem essa flag o Nikto aborta com `+ ERROR: Output file format
///   specified without a name`, e escrever em arquivo é incompatível com o
///   filesystem somente leitura do executor.
/// - `-ask no` impede o prompt "submit this information to CIRT.net", que
///   contaminaria o JSON com texto interativo.
/// - `-nointeractive` desliga perguntas interativas em geral.
/// - `-maxtime` limita o tempo por host, mantendo a execução dentro do timeout
///   do executor.
pub fn container_arguments(target: &str) -> Vec<String> {
    vec![
        "nikto.pl".to_string(),
        "-h".to_string(),
        target.to_string(),
        "-nointeractive".to_string(),
        "-ask".to_string(),
        "no".to_string(),
        "-maxtime".to_string(),
        "10m".to_string(),
        "-Format".to_string(),
        "json".to_string(),
        "-o".to_string(),
        "-".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_structured_json_to_stdout_without_a_shell() {
        let arguments = container_arguments("http://169.254.1.2:3000");

        assert_eq!(
            arguments,
            [
                "nikto.pl",
                "-h",
                "http://169.254.1.2:3000",
                "-nointeractive",
                "-ask",
                "no",
                "-maxtime",
                "10m",
                "-Format",
                "json",
                "-o",
                "-"
            ]
        );
    }

    #[test]
    fn command_never_introduces_a_shell_metacharacter() {
        let arguments = container_arguments("http://alvo.local:8080");

        for argument in &arguments {
            assert!(!argument.contains('|'));
            assert!(!argument.contains('>'));
            assert!(!argument.contains('<'));
            assert!(!argument.contains(';'));
            assert!(!argument.contains('$'));
            assert!(!argument.contains('&'));
        }
    }

    #[test]
    fn pins_the_image_by_digest_and_registers_the_version() {
        assert!(NIKTO_IMAGE.contains("@sha256:"));
        assert!(!NIKTO_VERSION.is_empty());
    }
}
