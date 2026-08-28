#[allow(dead_code)]
#[path = "../src/orchestrator/sandbox.rs"]
mod sandbox;

use sandbox::{ExecutionStatus, PodmanExecutor};
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;

const TEST_IMAGE: &str = "docker.io/library/alpine:3.20";

struct HostSentinel(PathBuf);

impl HostSentinel {
    fn create() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "smartsec-host-sentinel-{}-{unique}",
            std::process::id()
        ));
        fs::write(&path, b"host-only").expect("a sentinela do host deve ser criada");
        Self(path)
    }
}

impl Drop for HostSentinel {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn isolates_process_captures_io_and_removes_container() {
    match Command::new("podman").arg("--version").output().await {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            eprintln!("teste de integração do Podman ignorado: Podman não está instalado");
            return;
        }
        Err(error) => panic!("não foi possível verificar a disponibilidade do Podman: {error}"),
        Ok(output) => assert!(output.status.success(), "falha em `podman --version`"),
    }

    let sentinel = HostSentinel::create();
    let executor = PodmanExecutor::new(Duration::from_secs(120));
    let command = [
        "sh".to_owned(),
        "-c".to_owned(),
        "printf 'isolated stdout'; printf 'isolated stderr' >&2; test ! -e \"$1\"".to_owned(),
        "smartsec-test".to_owned(),
        sentinel.0.to_string_lossy().into_owned(),
    ];

    let result = executor
        .execute(TEST_IMAGE, &command)
        .await
        .expect("o Podman rootless deve executar o container isolado de teste");

    assert_eq!(result.status, ExecutionStatus::Succeeded);
    assert_eq!(result.stdout, "isolated stdout");
    assert_eq!(result.stderr, "isolated stderr");
    assert_eq!(result.cleanup_error, None);

    let inspect = Command::new("podman")
        .args(["container", "exists", &result.container_id])
        .status()
        .await
        .expect("o Podman deve permanecer disponível após o teste");
    assert!(!inspect.success(), "o container de teste não foi removido");
}
