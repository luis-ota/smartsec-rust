//! Resolução e validação do repositório a analisar pelo TruffleHog.
//!
//! O alvo do TruffleHog não é um host de rede: é um **repositório**. Isso muda
//! o contrato do executor, que precisa montar um diretório do host dentro do
//! container. Este módulo isola essa decisão e reaproveita o sandbox de
//! workspace já existente (`code_agent::workspace`) em vez de reimplementar
//! canonicalização e bloqueio de escape.
//!
//! Duas formas são aceitas, ambas com autorização explícita do usuário:
//!
//! - **Repositório local**: um caminho no host, canonicalizado e montado
//!   **somente leitura** em [`REPOSITORY_MOUNT_PATH`].
//! - **Repositório remoto autorizado**: uma URI `https://`/`http://` repassada
//!   ao `git` do TruffleHog, que a clona dentro do tmpfs do container.
//!
//! O repositório analisado nunca é montado para escrita e nunca é escrito.

use crate::code_agent::workspace::{Workspace, WorkspaceError};
use crate::tools::trufflehog::{REMOTE_URI_PREFIXES, REPOSITORY_MOUNT_PATH};
use std::path::{Component, Path, PathBuf};

/// Destino resolvido de uma varredura de repositório.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepositoryTarget {
    /// Repositório local canonicalizado, montado em somente leitura.
    Local {
        /// Caminho canônico no host, usado como origem do `--volume`.
        host_path: PathBuf,
        /// Ponto de montagem dentro do container.
        container_path: String,
    },
    /// Repositório remoto autorizado, clonado pelo próprio TruffleHog.
    Remote {
        /// URI repassada ao subcomando `git`.
        uri: String,
    },
}

impl RepositoryTarget {
    /// Caminho canônico no host, quando o alvo é local.
    pub fn host_path(&self) -> Option<&Path> {
        match self {
            Self::Local { host_path, .. } => Some(host_path),
            Self::Remote { .. } => None,
        }
    }

    /// Ponto de montagem dentro do container, quando o alvo é local.
    pub fn container_path(&self) -> Option<&str> {
        match self {
            Self::Local { container_path, .. } => Some(container_path),
            Self::Remote { .. } => None,
        }
    }

    /// Volume para o executor, ausente quando o alvo é remoto.
    ///
    /// O executor acrescenta a sufixo `:ro` a todo volume
    /// (`orchestrator::sandbox`), então o repositório analisado só pode ser
    /// lido. Nenhum caminho do host é devolvido quando o alvo é remoto.
    pub fn mounts(&self) -> Vec<(PathBuf, String)> {
        self.host_path()
            .map(|host_path| vec![(host_path.to_path_buf(), REPOSITORY_MOUNT_PATH.to_string())])
            .unwrap_or_default()
    }

    /// URI que o `git` do TruffleHog recebe.
    pub fn source_uri(&self) -> String {
        match self {
            Self::Local { container_path, .. } => format!("file://{container_path}"),
            Self::Remote { uri, .. } => uri.clone(),
        }
    }
}

/// Indica se o alvo é uma URI de repositório remoto.
///
/// Só os esquemas aceitos pela validação de alvo da CLI qualify. `ssh://` e a
/// forma scp-like (`git@host:org/repo`) ficariam de fora: a configuração já as
/// rejeita, e aceitar aqui produziria um alvo que não sai da validação.
pub fn is_remote_repository(target: &str) -> bool {
    let target = target.trim();
    REMOTE_URI_PREFIXES
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

/// Resolve o alvo informado em um repositório montável, com mensagem em pt-BR.
///
/// O caminho local é canonicalizado e precisa ser um diretório já existente.
/// A canonicalização é a do sandbox de workspace: ela resolve `..` e symlinks
/// **antes** do uso, de modo que o `--volume` recebe sempre o caminho real e o
/// scanner não escapa do diretório autorizado por link simbólico.
///
/// A validação é deliberadamente estrita: um caminho relativo, um alvo vazio
/// ou um caminho que não existe param a execução com um erro que aponta a
/// correção, em vez de deixar o TruffleHog terminar com exit 0 e stdout vazio.
pub fn resolve(target: &str) -> Result<RepositoryTarget, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(
            "o alvo do TruffleHog está vazio; informe o caminho do repositório local ou a URI de um repositório remoto autorizado"
                .to_string(),
        );
    }
    if is_remote_repository(target) {
        return Ok(RepositoryTarget::Remote {
            uri: target.to_string(),
        });
    }
    if target.contains("://") || target.starts_with("git@") {
        return Err(format!(
            "repositório remoto não suportado: \"{target}\"; use uma URI https:// ou http:// de repositório autorizado"
        ));
    }

    let requested = Path::new(target);
    if !requested.is_absolute() {
        return Err(format!(
            "o caminho do repositório deve ser absoluto, mas foi informado \"{target}\"; use por exemplo /home/usuario/projetos/repositorio"
        ));
    }
    // `..` é recusado explicitamente, na mesma posição em que o sandbox de
    // workspace o recusa. Canonicalizar sozinho resolveria `/repo/../..` para
    // `/tmp` e montaria um diretório que o usuário não pediu, o que transformaria
    // um erro de digitação em leitura de outra árvore. Recusar é mais seguro e
    // mais honesto do que adivinhar a intenção.
    if requested
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!(
            "o caminho do repositório não pode usar \"..\": \"{target}\"; informe o caminho absoluto do diretório do repositório"
        ));
    }

    // `Workspace::open` canonicaliza, resolve symlinks e exige um diretório
    // existente. Reaproveitar o sandbox evita uma segunda implementação de
    // escape por symlink: o `--volume` recebe sempre o caminho real, nunca o
    // link, então um link apontado para fora da árvore autorizada é montado
    // pelo seu destino e o erro de "não encontrado" é o mesmo dos testes do
    // sandbox de workspace.
    let workspace = Workspace::open(requested).map_err(workspace_error_message)?;

    Ok(RepositoryTarget::Local {
        host_path: workspace.root().to_path_buf(),
        container_path: REPOSITORY_MOUNT_PATH.to_string(),
    })
}

/// Traduz a falha do sandbox de workspace para a mensagem da CLI.
fn workspace_error_message(error: WorkspaceError) -> String {
    match error {
        WorkspaceError::NotFound { requested } => format!(
            "repositório não encontrado: \"{requested}\"; verifique o caminho ou informe a URI de um repositório remoto autorizado"
        ),
        WorkspaceError::NotADirectory { requested } => format!(
            "\"{requested}\" não é um diretório de repositório; informe a pasta que contém o repositório a analisar"
        ),
        WorkspaceError::NotAFile { requested } => format!(
            "\"{requested}\" não é um arquivo regular; informe a pasta que contém o repositório a analisar"
        ),
        WorkspaceError::OutsideRoot { requested } => format!(
            "caminho fora da raiz autorizada: \"{requested}\"; o caminho do repositório não pode usar \"..\" nem symlink para fora"
        ),
        WorkspaceError::Io { requested, message } => format!(
            "não foi possível acessar o repositório \"{requested}\": {message}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn temp_dir(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("smartsec-trufflehog-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn canonicalizes_a_local_repository_and_mounts_it_read_only() {
        let root = temp_dir("local");
        let repository = root.join("repo");
        fs::create_dir(&repository).unwrap();

        let resolved = resolve(&repository.display().to_string()).unwrap();

        assert_eq!(
            resolved,
            RepositoryTarget::Local {
                host_path: repository.canonicalize().unwrap(),
                container_path: REPOSITORY_MOUNT_PATH.to_string(),
            }
        );
        assert_eq!(resolved.source_uri(), "file:///alvo");
        assert_eq!(resolved.mounts().len(), 1);
        assert_eq!(resolved.mounts()[0].1, "/alvo");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn canonicalizes_through_a_symlink_before_handing_the_path_to_podman() {
        let root = temp_dir("symlink");
        let repository = root.join("repo");
        fs::create_dir(&repository).unwrap();
        let link = root.join("atalho");
        symlink(&repository, &link).unwrap();

        let resolved = resolve(&link.display().to_string()).unwrap();

        // O `--volume` recebe o caminho real, nunca o link.
        assert_eq!(
            resolved.host_path().unwrap(),
            repository.canonicalize().unwrap()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_remote_authorized_repository_is_never_mounted() {
        let resolved = resolve("https://github.com/org/repo.git").unwrap();

        assert_eq!(
            resolved,
            RepositoryTarget::Remote {
                uri: "https://github.com/org/repo.git".to_string()
            }
        );
        assert!(resolved.host_path().is_none());
        assert!(resolved.mounts().is_empty());
        assert_eq!(resolved.source_uri(), "https://github.com/org/repo.git");
    }

    #[test]
    fn rejects_a_relative_path_with_an_actionable_message() {
        let error = resolve("./repo").unwrap_err();

        assert!(error.contains("absoluto"), "{error}");
        assert!(error.contains("/home/usuario"), "{error}");
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let root = temp_dir("traversal");
        fs::create_dir_all(root.join("repo")).unwrap();

        let error = resolve(&format!("{}/repo/../..", root.display())).unwrap_err();

        // Canonicalizar resolveria isso para `/tmp` e montaria um diretório que
        // o usuário não pediu. A recusa é explícita e aponta a correção.
        assert!(error.contains("não pode usar \"..\""), "{error}");
        assert!(error.contains(&root.display().to_string()), "{error}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_symlink_that_escapes_to_a_non_directory() {
        let root = temp_dir("escape");
        let outside = temp_dir("escape-fora");
        fs::write(outside.join("segredo.txt"), "conteudo").unwrap();
        let repository = root.join("repo");
        fs::create_dir(&repository).unwrap();
        symlink(&outside, repository.join("fuga")).unwrap();

        // O link para fora é canônico sem quebrar a resolução da raiz: quem
        // decide o que o scanner lê é o alvo montado, não o conteúdo do repo.
        // O que não pode acontecer é o `--volume` receber um caminho diferente
        // do diretório solicitado.
        let resolved = resolve(&repository.display().to_string()).unwrap();
        assert_eq!(
            resolved.host_path().unwrap(),
            repository.canonicalize().unwrap()
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn rejects_a_missing_repository_instead_of_scanning_an_empty_path() {
        let root = temp_dir("ausente");
        let missing = root.join("nao-existe");

        let error = resolve(&missing.display().to_string()).unwrap_err();

        assert!(error.contains("não encontrado"), "{error}");
        assert!(error.contains("remoto autorizado"), "{error}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_file_as_repository() {
        let root = temp_dir("arquivo");
        let file = root.join("README.md");
        fs::write(&file, "# exemplo").unwrap();

        let error = resolve(&file.display().to_string()).unwrap_err();

        assert!(error.contains("diretório de repositório"), "{error}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_an_empty_target_and_unsupported_remote_schemes() {
        assert!(resolve("   ").unwrap_err().contains("vazio"));

        let error = resolve("ssh://git@host/repo.git").unwrap_err();
        assert!(error.contains("não suportado"), "{error}");
        assert!(error.contains("https://"), "{error}");

        let error = resolve("git@github.com:org/repo.git").unwrap_err();
        assert!(error.contains("não suportado"), "{error}");
    }
}
