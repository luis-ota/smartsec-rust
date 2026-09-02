use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const PODMAN_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    Succeeded,
    Failed(Option<i32>),
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub status: ExecutionStatus,
    pub duration: Duration,
    pub container_id: String,
    pub cleanup_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PodmanExecutor {
    binary: PathBuf,
    timeout: Duration,
}

impl PodmanExecutor {
    pub fn new(timeout: Duration) -> Self {
        Self {
            binary: PathBuf::from("podman"),
            timeout,
        }
    }

    #[cfg(test)]
    fn with_binary(binary: PathBuf, timeout: Duration) -> Self {
        Self { binary, timeout }
    }

    pub async fn execute(
        &self,
        image: &str,
        command: &[String],
    ) -> anyhow::Result<ExecutionResult> {
        self.ensure_rootless().await?;

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!(
            "smartsec-{}-{created_at}-{}",
            std::process::id(),
            CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut cleanup_guard = ContainerCleanup::new(self.binary.clone(), &name);
        let mut create_command = self.podman_command();
        create_command
            .args([
                "create",
                "--name",
                &name,
                "--network",
                "slirp4netns",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--pids-limit",
                "256",
                "--cap-drop",
                "all",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=128m",
                image,
            ])
            .args(command);
        let create_output = match tokio::time::timeout(self.timeout, create_command.output()).await
        {
            Ok(output) => output.with_context(|| self.unavailable_message())?,
            Err(_) => {
                let cleanup = self.remove_container(&name).await.err();
                if cleanup.is_none() {
                    cleanup_guard.disarm();
                }
                return Err(anyhow!(
                    "Podman não criou a imagem '{image}' dentro de {:.2?}. {}",
                    self.timeout,
                    cleanup.map_or_else(
                        || "O container parcial foi removido.".to_owned(),
                        |error| format!(
                            "Falha na limpeza: {error:#}. Execute `podman rm --force {name}`."
                        )
                    )
                ));
            }
        };

        if !create_output.status.success() {
            let cleanup_error = self.remove_container(&name).await.err();
            if cleanup_error.is_none() {
                cleanup_guard.disarm();
            }
            return Err(anyhow!(
                "Podman não conseguiu criar o container rootless a partir da imagem '{image}': {}. Verifique o nome da imagem, o acesso ao registro de imagens e a configuração do armazenamento rootless.{}",
                output_message(&create_output.stderr),
                cleanup_error.map_or_else(String::new, |error| format!(
                    " A limpeza também falhou: {error:#}. Execute `podman rm --force --ignore {name}`."
                ))
            ));
        }

        let container_id = String::from_utf8_lossy(&create_output.stdout)
            .trim()
            .to_owned();
        if container_id.is_empty() {
            let cleanup = self.remove_container(&name).await.err();
            if cleanup.is_none() {
                cleanup_guard.disarm();
            }
            return Err(anyhow!(
                "Podman criou o container '{name}', mas não retornou o ID do container. Resultado da limpeza: {}",
                cleanup.map_or_else(
                    || "container removido".to_owned(),
                    |error| format!("{error:#}; remova-o com `podman rm --force {name}`")
                )
            ));
        }

        let execution = self.run_attached(&container_id).await;
        let cleanup_error = self
            .remove_container(&container_id)
            .await
            .err()
            .map(|error| {
                format!("{error:#}. Remova-o manualmente com `podman rm --force {container_id}`")
            });
        if cleanup_error.is_none() {
            cleanup_guard.disarm();
        }

        let (stdout, stderr, status, duration) = match execution {
            Ok(execution) => execution,
            Err(error) => {
                return Err(match cleanup_error {
                    Some(cleanup_error) => anyhow!(
                        "Falha na execução pelo Podman: {error:#}. A limpeza também falhou: {cleanup_error}"
                    ),
                    None => error,
                });
            }
        };
        Ok(ExecutionResult {
            stdout,
            stderr,
            status,
            duration,
            container_id,
            cleanup_error,
        })
    }

    async fn ensure_rootless(&self) -> anyhow::Result<()> {
        let mut command = self.podman_command();
        command.args(["info", "--format", "{{.Host.Security.Rootless}}"]);
        let output = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, command.output())
            .await
            .context(
                "Podman não respondeu à verificação de disponibilidade rootless em até 10 segundos",
            )?
            .with_context(|| self.unavailable_message())?;

        if !output.status.success() {
            return Err(anyhow!(
                "Podman está instalado, mas indisponível: {}. Inicie o serviço rootless do Podman ou execute `podman system migrate` e tente novamente.",
                output_message(&output.stderr)
            ));
        }
        if String::from_utf8_lossy(&output.stdout).trim() != "true" {
            return Err(anyhow!(
                "Podman não está em modo rootless. Execute o SmartSec como usuário comum e confirme que `podman info --format '{{{{.Host.Security.Rootless}}}}'` retorna true."
            ));
        }
        Ok(())
    }

    async fn run_attached(
        &self,
        container_id: &str,
    ) -> anyhow::Result<(String, String, ExecutionStatus, Duration)> {
        let mut child = self
            .podman_command()
            .args(["start", "--attach", container_id])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Podman não conseguiu iniciar o container criado")?;
        let stdout = child
            .stdout
            .take()
            .context("não foi possível capturar o stdout do Podman")?;
        let stderr = child
            .stderr
            .take()
            .context("não foi possível capturar o stderr do Podman")?;
        let stdout_task = tokio::spawn(read_stream(stdout));
        let stderr_task = tokio::spawn(read_stream(stderr));
        let started_at = Instant::now();

        let status = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(wait_result) => {
                let exit = wait_result.context("falha ao aguardar o processo do Podman")?;
                if exit.success() {
                    ExecutionStatus::Succeeded
                } else {
                    ExecutionStatus::Failed(exit.code())
                }
            }
            Err(_) => {
                let _ = child.kill().await;
                let mut kill_command = self.podman_command();
                kill_command.args(["kill", container_id]);
                let _ = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, kill_command.output()).await;
                ExecutionStatus::TimedOut
            }
        };

        let stdout = stdout_task
            .await
            .context("falha na tarefa de captura do stdout")?
            .context("não foi possível ler o stdout do Podman")?;
        let stderr = stderr_task
            .await
            .context("falha na tarefa de captura do stderr")?
            .context("não foi possível ler o stderr do Podman")?;

        Ok((
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            status,
            started_at.elapsed(),
        ))
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        let mut command = self.podman_command();
        command.args(["rm", "--force", "--ignore", container_id]);
        let output = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, command.output())
            .await
            .context("a limpeza do Podman não terminou em até 10 segundos")?
            .context("falha ao executar a limpeza pelo Podman")?;
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Podman não conseguiu remover o container {container_id}: {}",
                output_message(&output.stderr)
            ))
        }
    }

    fn podman_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.kill_on_drop(true);
        command
    }

    fn unavailable_message(&self) -> String {
        format!(
            "Podman não foi encontrado em '{}'. Instale o Podman e configure o uso rootless antes de habilitar varreduras reais",
            self.binary.display()
        )
    }
}

struct ContainerCleanup {
    binary: PathBuf,
    container_id: Option<String>,
}

impl ContainerCleanup {
    fn new(binary: PathBuf, container_id: &str) -> Self {
        Self {
            binary,
            container_id: Some(container_id.to_owned()),
        }
    }

    fn disarm(&mut self) {
        self.container_id = None;
    }
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let Some(container_id) = self.container_id.take() else {
            return;
        };
        let Ok(mut child) = std::process::Command::new(&self.binary)
            .args(["rm", "--force", "--ignore", &container_id])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn output_message(stderr: &[u8]) -> String {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    if message.is_empty() {
        "nenhuma saída de diagnóstico foi fornecida".to_owned()
    } else {
        message.to_owned()
    }
}

async fn read_stream<R>(mut stream: R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

#[async_trait]
pub trait SandboxManager: Send + Sync {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error>;

    fn run_command(&self, container_id: &str, command: &str) -> Result<String, anyhow::Error>;

    fn destroy_environment(&self, container_id: &str) -> Result<(), anyhow::Error>;
}

pub struct LocalSandbox;

#[async_trait]
#[allow(dead_code)]
impl SandboxManager for LocalSandbox {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error> {
        Ok(format!(
            "local-{}",
            image_name.replace(':', "-").replace('/', "_")
        ))
    }

    fn run_command(&self, _container_id: &str, command: &str) -> Result<String, anyhow::Error> {
        Ok(format!("[local-sandbox] $ {}", command))
    }

    fn destroy_environment(&self, _container_id: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct MockSandbox;

#[async_trait]
impl SandboxManager for MockSandbox {
    fn create_isolated_environment(&self, image_name: &str) -> Result<String, anyhow::Error> {
        Ok(format!("mock-{}", image_name))
    }

    fn run_command(&self, container_id: &str, command: &str) -> Result<String, anyhow::Error> {
        Ok(format!("[mock-sandbox:{}] $ {}", container_id, command))
    }

    fn destroy_environment(&self, _container_id: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    struct FakePodman {
        directory: PathBuf,
        binary: PathBuf,
        log: PathBuf,
    }

    impl FakePodman {
        fn new(start_script: &str) -> Self {
            Self::with_cleanup(start_script, "exit 0")
        }

        fn with_cleanup(start_script: &str, cleanup_script: &str) -> Self {
            Self::with_scripts("printf 'container-123\\n'", start_script, cleanup_script)
        }

        fn with_scripts(create_script: &str, start_script: &str, cleanup_script: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "smartsec-podman-test-{}-{}",
                std::process::id(),
                CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            let binary = directory.join("podman");
            let log = directory.join("calls.log");
            fs::write(directory.join("create.sh"), create_script).unwrap();
            fs::write(directory.join("start.sh"), start_script).unwrap();
            fs::write(directory.join("cleanup.sh"), cleanup_script).unwrap();
            symlink(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_podman"),
                &binary,
            )
            .unwrap();
            Self {
                directory,
                binary,
                log,
            }
        }

        fn calls(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    impl Drop for FakePodman {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn captures_successful_execution_and_removes_container() {
        let fake = FakePodman::new("printf 'scanner output'; printf 'scanner warning' >&2");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));

        let result = executor
            .execute(
                "example/scanner:1",
                &["scan".to_owned(), "target".to_owned()],
            )
            .await
            .unwrap();

        assert_eq!(result.stdout, "scanner output");
        assert_eq!(result.stderr, "scanner warning");
        assert_eq!(result.status, ExecutionStatus::Succeeded);
        assert_eq!(result.container_id, "container-123");
        assert_eq!(result.cleanup_error, None);
        assert!(result.duration <= Duration::from_secs(1));
        let calls = fake.calls();
        assert!(calls.contains("create --name smartsec-"));
        assert!(calls.contains("--cap-drop all"));
        assert!(calls.contains("--read-only"));
        assert!(calls.contains("example/scanner:1 scan target"));
        assert!(calls.contains("rm --force --ignore container-123"));
    }

    #[tokio::test]
    async fn returns_nonzero_status_and_still_removes_container() {
        let fake = FakePodman::new("printf 'invalid target' >&2; exit 7");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));

        let result = executor.execute("scanner", &[]).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Failed(Some(7)));
        assert_eq!(result.stderr, "invalid target");
        assert!(fake.calls().contains("rm --force --ignore container-123"));
    }

    #[tokio::test]
    async fn times_out_kills_and_removes_container() {
        let fake = FakePodman::new("exec sleep 10");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));

        let result = executor.execute("scanner", &[]).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::TimedOut);
        let calls = fake.calls();
        assert!(calls.contains("kill container-123"));
        assert!(calls.contains("rm --force --ignore container-123"));
    }

    #[tokio::test]
    async fn reports_missing_podman_with_remediation() {
        let executor = PodmanExecutor::with_binary(
            Path::new("/definitely/missing/podman").to_owned(),
            Duration::from_secs(1),
        );

        let error = executor.execute("scanner", &[]).await.unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("Instale o Podman"));
        assert!(message.contains("rootless"));
    }

    #[tokio::test]
    async fn cancellation_still_removes_container() {
        let fake = FakePodman::new("exec sleep 10");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(30));
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        for _ in 0..50 {
            if fake.calls().contains("start --attach container-123") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        let _ = task.await;

        for _ in 0..50 {
            if fake.calls().contains("rm --force --ignore smartsec-") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(fake.calls().contains("rm --force --ignore smartsec-"));
    }

    #[tokio::test]
    async fn exposes_cleanup_failure_with_manual_remediation() {
        let fake = FakePodman::with_cleanup("exit 0", "printf 'storage busy' >&2; exit 1");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));

        let result = executor.execute("scanner", &[]).await.unwrap();

        let cleanup_error = result.cleanup_error.unwrap();
        assert!(cleanup_error.contains("storage busy"));
        assert!(cleanup_error.contains("podman rm --force container-123"));
    }

    #[tokio::test]
    async fn cancellation_during_creation_removes_container_by_name() {
        let fake = FakePodman::with_scripts("exec sleep 10", "exit 0", "exit 0");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(30));
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        for _ in 0..50 {
            if fake.calls().contains("create --name smartsec-") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        let _ = task.await;

        for _ in 0..50 {
            if fake.calls().contains("rm --force --ignore smartsec-") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(fake.calls().contains("rm --force --ignore smartsec-"));
    }
}
