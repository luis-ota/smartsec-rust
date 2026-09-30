#[path = "../src/utils/redaction.rs"]
pub mod redaction;

pub mod utils {
    pub use crate::redaction;
}

/// O executor depende apenas do canal de controle, que não tem outras
/// dependências do projeto; ele é incluído aqui para o teste de integração.
#[allow(dead_code)]
#[path = "../src/orchestrator/control.rs"]
pub mod control;

pub mod orchestrator {
    pub use crate::control;
}

#[allow(dead_code)]
#[path = "../src/orchestrator/sandbox.rs"]
mod sandbox;

use control::ControlChannel;
use sandbox::{ExecutionStatus, PodmanExecutor};
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::{Mutex, MutexGuard};

const TEST_IMAGE: &str = "docker.io/library/alpine:3.20";

/// Serializa os testes que inspecionam containers reais.
///
/// O executor nomeia os containers com `smartsec-<pid>-...`, e o PID é o do
/// processo de teste. Sem serializar, dois testes simultâneos enxergam o
/// container um do outro e cancelam a varredura errada. O mutex é do Tokio
/// porque o guard é mantido através de `await`.
async fn real_container_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

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

/// Aguarda o container de teste subir, com um limite de tempo explícito.
async fn wait_for_smartsec_container() -> String {
    for _ in 0..120 {
        if let Some(name) = running_smartsec_container().await {
            return name;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("o container de teste não subiu a tempo");
}

/// Consulta o estado de pausa do container diretamente no Podman.
async fn container_paused(name: &str) -> bool {
    let output = Command::new("podman")
        .args(["inspect", "--format", "{{.State.Paused}}", name])
        .output()
        .await
        .expect("o Podman deve permitir inspecionar o container");
    String::from_utf8_lossy(&output.stdout).trim() == "true"
}

/// Nome do primeiro container `smartsec-` em execução, se houver.
async fn running_smartsec_container() -> Option<String> {
    let output = Command::new("podman")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
        .await
        .expect("o Podman deve permanecer disponível");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("smartsec-"))
        .map(str::to_owned)
}

/// Indica se há Podman utilizável; sem ele o teste de integração é ignorado.
async fn podman_available() -> bool {
    match Command::new("podman").arg("--version").output().await {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            eprintln!("teste de integração do Podman ignorado: Podman não está instalado");
            false
        }
        Err(error) => panic!("não foi possível verificar a disponibilidade do Podman: {error}"),
        Ok(output) => {
            assert!(output.status.success(), "falha em `podman --version`");
            true
        }
    }
}

#[tokio::test]
async fn isolates_process_captures_io_and_removes_container() {
    if !podman_available().await {
        return;
    }

    let _lock = real_container_lock().await;
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

#[tokio::test]
async fn cancelling_a_real_container_stops_and_removes_it() {
    if !podman_available().await {
        return;
    }

    let _lock = real_container_lock().await;
    let control = ControlChannel::new();
    let executor = PodmanExecutor::new(Duration::from_secs(120)).with_control(&control);
    let command = [
        "sh".to_owned(),
        "-c".to_owned(),
        "printf 'iniciando'; exec sleep 60".to_owned(),
    ];
    let task = tokio::spawn(async move { executor.execute(TEST_IMAGE, &command).await });

    // Espera o container real existir e estar rodando antes de cancelar.
    let name = wait_for_smartsec_container().await;

    let state = Command::new("podman")
        .args(["inspect", "--format", "{{.State.Paused}}", &name])
        .output()
        .await
        .expect("o Podman deve permitir inspecionar o container");
    assert_eq!(
        String::from_utf8_lossy(&state.stdout).trim(),
        "false",
        "o container precisa estar em execução antes do cancelamento"
    );

    control.cancel();
    let result = tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("o cancelamento não pode travar a execução")
        .expect("a task não pode entrar em pânico")
        .expect("o cancelamento cooperativo não pode ser um erro");

    assert_eq!(result.status, ExecutionStatus::Cancelled);
    let exists = Command::new("podman")
        .args(["container", "exists", &name])
        .status()
        .await
        .expect("o Podman deve permanecer disponível");
    assert!(
        !exists.success(),
        "o container cancelado não pode ficar órfão"
    );
    let trace = result.trace.join("\n");
    assert!(trace.contains("$ podman stop --time 5"), "{trace}");
    // A remoção usa o ID devolvido pelo `create`, não o nome escolhido.
    assert!(
        trace.contains(&format!(
            "$ podman rm --force --ignore {}",
            result.container_id
        )),
        "{trace}"
    );
}

#[tokio::test]
async fn pausing_a_real_container_freezes_it_and_resuming_frees_it() {
    if !podman_available().await {
        return;
    }

    let _lock = real_container_lock().await;
    let control = ControlChannel::new();
    let executor = PodmanExecutor::new(Duration::from_secs(120)).with_control(&control);
    let command = [
        "sh".to_owned(),
        "-c".to_owned(),
        "printf 'iniciando'; exec sleep 60".to_owned(),
    ];
    let task = tokio::spawn(async move { executor.execute(TEST_IMAGE, &command).await });

    let name = wait_for_smartsec_container().await;

    let target = name.clone();
    control.pause();
    for _ in 0..80 {
        if container_paused(&target).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        container_paused(&target).await,
        "a pausa precisa congelar o container real"
    );

    control.resume();
    for _ in 0..80 {
        if !container_paused(&target).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !container_paused(&target).await,
        "a retomada precisa liberar o container real"
    );

    control.cancel();
    let result = tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("o cancelamento não pode travar a execução")
        .expect("a task não pode entrar em pânico")
        .expect("o cancelamento cooperativo não pode ser um erro");
    assert_eq!(result.status, ExecutionStatus::Cancelled);
    let exists = Command::new("podman")
        .args(["container", "exists", &name])
        .status()
        .await
        .expect("o Podman deve permanecer disponível");
    assert!(!exists.success(), "o container não pode ficar órfão");
}
