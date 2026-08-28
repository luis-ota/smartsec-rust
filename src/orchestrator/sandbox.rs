use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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

        let name = format!(
            "smartsec-{}-{}",
            std::process::id(),
            CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let create_output = self
            .podman_command()
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
            .args(command)
            .output()
            .await
            .with_context(|| self.unavailable_message())?;

        if !create_output.status.success() {
            return Err(anyhow!(
                "Podman could not create the rootless container from image '{image}': {}. Verify the image name, registry access, and rootless storage configuration.",
                output_message(&create_output.stderr)
            ));
        }

        let container_id = String::from_utf8_lossy(&create_output.stdout)
            .trim()
            .to_owned();
        if container_id.is_empty() {
            return Err(anyhow!(
                "Podman created container '{name}' but returned no container ID; remove it with `podman rm --force {name}`"
            ));
        }

        let execution = self.run_attached(&container_id).await;
        let cleanup_error = self
            .remove_container(&container_id)
            .await
            .err()
            .map(|error| {
                format!("{error:#}. Remove it manually with `podman rm --force {container_id}`")
            });

        let (stdout, stderr, status, duration) = execution?;
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
        let output = self
            .podman_command()
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()
            .await
            .with_context(|| self.unavailable_message())?;

        if !output.status.success() {
            return Err(anyhow!(
                "Podman is installed but unavailable: {}. Start the rootless Podman service or run `podman system migrate`, then retry.",
                output_message(&output.stderr)
            ));
        }
        if String::from_utf8_lossy(&output.stdout).trim() != "true" {
            return Err(anyhow!(
                "Podman is not running rootless. Run SmartSec as a regular user and verify `podman info --format '{{{{.Host.Security.Rootless}}}}'` returns true."
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
            .context("Podman failed to start the created container")?;
        let stdout = child
            .stdout
            .take()
            .context("could not capture Podman stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("could not capture Podman stderr")?;
        let stdout_task = tokio::spawn(read_stream(stdout));
        let stderr_task = tokio::spawn(read_stream(stderr));
        let started_at = Instant::now();

        let status = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(wait_result) => {
                let exit = wait_result.context("failed while waiting for the Podman process")?;
                if exit.success() {
                    ExecutionStatus::Succeeded
                } else {
                    ExecutionStatus::Failed(exit.code())
                }
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = self
                    .podman_command()
                    .args(["kill", container_id])
                    .output()
                    .await;
                ExecutionStatus::TimedOut
            }
        };

        let stdout = stdout_task
            .await
            .context("stdout capture task failed")?
            .context("could not read Podman stdout")?;
        let stderr = stderr_task
            .await
            .context("stderr capture task failed")?
            .context("could not read Podman stderr")?;

        Ok((
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            status,
            started_at.elapsed(),
        ))
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        let output = self
            .podman_command()
            .args(["rm", "--force", container_id])
            .output()
            .await
            .context("failed to invoke Podman cleanup")?;
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Podman failed to remove container {container_id}: {}",
                output_message(&output.stderr)
            ))
        }
    }

    fn podman_command(&self) -> Command {
        Command::new(&self.binary)
    }

    fn unavailable_message(&self) -> String {
        format!(
            "Podman was not found at '{}'. Install Podman and configure it for rootless use before enabling real scans",
            self.binary.display()
        )
    }
}

fn output_message(stderr: &[u8]) -> String {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    if message.is_empty() {
        "no diagnostic output was provided".to_owned()
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
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    struct FakePodman {
        directory: PathBuf,
        binary: PathBuf,
        log: PathBuf,
    }

    impl FakePodman {
        fn new(start_script: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "smartsec-podman-test-{}-{}",
                std::process::id(),
                CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            let binary = directory.join("podman");
            let pending_binary = directory.join("podman.tmp");
            let log = directory.join("calls.log");
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\n  info) printf 'true\\n' ;;\n  create) printf 'container-123\\n' ;;\n  start) {} ;;\n  kill|rm) exit 0 ;;\nesac\n",
                log.display(),
                start_script
            );
            fs::write(&pending_binary, script).unwrap();
            let mut permissions = fs::metadata(&pending_binary).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&pending_binary, permissions).unwrap();
            fs::rename(pending_binary, &binary).unwrap();
            Self {
                directory,
                binary,
                log,
            }
        }

        fn calls(&self) -> String {
            fs::read_to_string(&self.log).unwrap()
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
        assert!(calls.contains("rm --force container-123"));
    }

    #[tokio::test]
    async fn returns_nonzero_status_and_still_removes_container() {
        let fake = FakePodman::new("printf 'invalid target' >&2; exit 7");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));

        let result = executor.execute("scanner", &[]).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Failed(Some(7)));
        assert_eq!(result.stderr, "invalid target");
        assert!(fake.calls().contains("rm --force container-123"));
    }

    #[tokio::test]
    async fn times_out_kills_and_removes_container() {
        let fake = FakePodman::new("exec sleep 10");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_millis(30));

        let result = executor.execute("scanner", &[]).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::TimedOut);
        let calls = fake.calls();
        assert!(calls.contains("kill container-123"));
        assert!(calls.contains("rm --force container-123"));
    }

    #[tokio::test]
    async fn reports_missing_podman_with_remediation() {
        let executor = PodmanExecutor::with_binary(
            Path::new("/definitely/missing/podman").to_owned(),
            Duration::from_secs(1),
        );

        let error = executor.execute("scanner", &[]).await.unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("Install Podman"));
        assert!(message.contains("rootless"));
    }
}
