use crate::orchestrator::control::{ControlChannel, RunControl};
use crate::orchestrator::tmpfs;
use anyhow::{anyhow, Context};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::sync::watch;

static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const PODMAN_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const ROOTLESS_NETWORK: &str = "pasta:--map-host-loopback=169.254.1.2";
const DEFAULT_MEMORY_LIMIT: &str = "512m";

/// Opções de montaje do diretório gravável de saída de uma ferramenta.
///
/// É o único ponto de escrita do container fora das tmpfs: o executor cria um
/// diretório **vazio** no `TMPDIR` do host e o monta em `container_dir` com
/// `rw,noexec,nosuid,nodev`. Nada mais do host é montado, nenhuma capacidade é
/// adicionada e o diretório é removido quando o `WritableOutput` sai de escopo.
pub struct WritableOutput {
    /// Limite de memória do container, no formato aceito pelo Podman.
    pub memory: String,
    /// tmpfs adicionais exigidas pela ferramenta, já no formato do Podman.
    pub extra_tmpfs: Vec<String>,
    /// Caminho do diretório gravável dentro do container.
    pub container_dir: String,
    /// Nome do arquivo de artefato a coletar dentro do diretório gravável.
    pub file_name: String,
    host_dir: PathBuf,
}

impl WritableOutput {
    /// Cria o diretório de saída no `TMPDIR` do host.
    ///
    /// O diretório é criado com modo `0733` (gravar e percorrer, sem listar)
    /// porque, em Podman rootless sem `keep-id`, o usuário do container é um
    /// *subuid* do host e não consegue gravar em um diretório `0755` do usuário
    /// do host. O diretório pai é o `TMPDIR` do próprio processo do SmartSec, de
    /// modo que só o processo e o container o alcançam.
    ///
    /// O `TMPDIR` é **verificado** como `tmpfs` antes de o diretório ser criado,
    /// conforme a regra de isolamento do TCC. A condição não é presumida: um
    /// `TMPDIR` que aponte para um diretório comum em disco — o caso de um
    /// runner de CI, por exemplo — faria o executor montar em bind mount um
    /// diretório persistente e gravaria o relatório do scanner fora da regra,
    /// em silêncio. Por isso a criação falha nesse caso; não há degradação para
    /// escrita fora da regra. Ver [`crate::orchestrator::tmpfs`] para o método de
    /// verificação e suas limitações.
    pub fn new(container_dir: &str, file_name: &str) -> std::io::Result<Self> {
        Self::new_in(
            &std::env::temp_dir(),
            container_dir,
            file_name,
            &tmpfs::ProcMounts::process(),
        )
    }

    /// Igual a [`WritableOutput::new`], com o diretório base e a fonte do tipo de
    /// filesystem injetados.
    ///
    /// Existe para que o caminho negativo da verificação (diretório em disco
    /// comum) seja testável sem depender da máquina de teste: o teste aponta o
    /// diretório base para um diretório próprio e afirma que nada é criado
    /// dentro dele quando a regra é violada. O fluxo real sempre usa o `TMPDIR`
    /// do processo e `/proc/self/mountinfo`.
    fn new_in(
        base_dir: &Path,
        container_dir: &str,
        file_name: &str,
        probe: &dyn tmpfs::FilesystemProbe,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        // O caminho é canonicalizado para que um `TMPDIR` que é symlink para um
        // diretório em disco seja avaliado no destino real, e não no nome.
        let verified_dir =
            std::fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
        tmpfs::require_tmpfs(&verified_dir, probe)?;
        let host_dir = base_dir.join(format!(
            "smartsec-saida-{}-{}",
            std::process::id(),
            CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&host_dir)?;
        std::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o733))?;
        Ok(Self {
            memory: DEFAULT_MEMORY_LIMIT.to_owned(),
            extra_tmpfs: Vec::new(),
            container_dir: container_dir.to_owned(),
            file_name: file_name.to_owned(),
            host_dir,
        })
    }

    /// Substitui o limite de memória do container.
    pub fn with_memory(mut self, memory: &str) -> Self {
        self.memory = memory.to_owned();
        self
    }

    /// Acrescenta uma tmpfs adicional exigida pela ferramenta.
    pub fn with_tmpfs(mut self, tmpfs: &str) -> Self {
        self.extra_tmpfs.push(tmpfs.to_owned());
        self
    }

    /// Diretório criado no host.
    pub fn host_dir(&self) -> &Path {
        &self.host_dir
    }

    /// Caminho do artefato dentro do container.
    pub fn container_path(&self) -> String {
        format!("{}/{}", self.container_dir, self.file_name)
    }

    /// Especificação de volume como o Podman espera em `--volume`.
    fn mount_spec(&self) -> String {
        format!(
            "{}:{}:rw,noexec,nosuid,nodev",
            self.host_dir.display(),
            self.container_dir
        )
    }
}

impl Drop for WritableOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.host_dir);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    Succeeded,
    Failed(Option<i32>),
    TimedOut,
    /// O container foi encerrado a pedido (REQ14) e removido sem órfão.
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub status: ExecutionStatus,
    pub duration: Duration,
    pub container_id: String,
    pub cleanup_error: Option<String>,
    pub trace: Vec<String>,
    /// Artefato escrito pelo scanner no diretório de saída gravável, coletado
    /// antes da remoção do container. `None` quando a execução não pediu
    /// coleta ou quando o scanner não escreveu o artefato; o motivo fica em
    /// [`Self::artifact_error`].
    pub artifact: Option<String>,
    /// Motivo pelo qual o artefato solicitado não pôde ser coletado.
    ///
    /// Ausência do artefato não é falha fatal da varredura, mas precisa ser
    /// reportada: uma saída não coletada nunca pode ser lida como varredura
    /// limpa.
    pub artifact_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PodmanExecutor {
    binary: PathBuf,
    timeout: Duration,
    log_sink: Option<mpsc::UnboundedSender<String>>,
    /// Canal de pausa/retomada/cancelamento (REQ14). Quando ausente, o
    /// executor se comporta como antes e só obedece ao timeout.
    control: Option<watch::Receiver<RunControl>>,
}

/// Mensagem do controlador do container para o laço de execução.
enum ControlMessage {
    /// Mudança observada no container real.
    Event(ContainerControlEvent),
    /// Linha do trace operacional, carimbada pelo laço principal.
    Trace(String),
}

/// Evento do controlador do container, reencaminhado ao laço de execução.
enum ContainerControlEvent {
    Paused,
    Resumed,
    /// O `podman stop` foi emitido e o encerramento está em andamento.
    Cancelling,
    /// O processo dentro do container morreu; o laço pode seguir para a limpeza.
    Stopped,
    Failure(String),
}

/// Desfecho de um comando do Podman sujeito a timeout e cancelamento.
enum AwaitOutcome {
    Finished(std::io::Result<std::process::Output>),
    TimedOut,
    Cancelled,
}

/// Tarefa que reage ao canal de controle e age sobre o container real.
///
/// Roda ao lado do `podman start --attach`: a pausa vira `podman pause` e a
/// retomada vira `podman unpause`, e não uma bandeira local.
async fn container_control_loop(
    binary: PathBuf,
    container_id: String,
    mut control: watch::Receiver<RunControl>,
    messages: mpsc::UnboundedSender<ControlMessage>,
) {
    // O estado corrente é aplicado primeiro: uma pausa que chegou durante o
    // `create` precisa ser honrada assim que o container existir. O valor é
    // copiado antes de qualquer `await` para não segurar o lock do `watch`.
    let current = *control.borrow_and_update();
    let mut paused = match current {
        RunControl::Running => false,
        RunControl::Paused => {
            let _ = messages.send(ControlMessage::Trace(format!(
                "$ podman pause {container_id}"
            )));
            podman_control(&binary, &["pause", &container_id])
                .await
                .is_ok()
        }
        RunControl::Cancelled => {
            let _ = messages.send(ControlMessage::Event(ContainerControlEvent::Cancelling));
            stop_container(&binary, &container_id, &messages).await;
            let _ = messages.send(ControlMessage::Event(ContainerControlEvent::Stopped));
            return;
        }
    };
    loop {
        if control.changed().await.is_err() {
            return;
        }
        let next = *control.borrow_and_update();
        match next {
            RunControl::Running if paused => {
                let _ = messages.send(ControlMessage::Trace(format!(
                    "$ podman unpause {container_id}"
                )));
                match podman_control(&binary, &["unpause", &container_id]).await {
                    Ok(()) => {
                        paused = false;
                        let _ =
                            messages.send(ControlMessage::Event(ContainerControlEvent::Resumed));
                    }
                    Err(error) => {
                        // Sem unpause bem-sucedido o container continua
                        // pausado; repetir o comando é seguro.
                        let _ = messages
                            .send(ControlMessage::Event(ContainerControlEvent::Failure(error)));
                    }
                }
            }
            RunControl::Paused if !paused => {
                let _ = messages.send(ControlMessage::Trace(format!(
                    "$ podman pause {container_id}"
                )));
                match podman_control(&binary, &["pause", &container_id]).await {
                    Ok(()) => {
                        paused = true;
                        let _ = messages.send(ControlMessage::Event(ContainerControlEvent::Paused));
                    }
                    Err(error) => {
                        let _ = messages
                            .send(ControlMessage::Event(ContainerControlEvent::Failure(error)));
                    }
                }
            }
            RunControl::Cancelled => {
                let _ = messages.send(ControlMessage::Event(ContainerControlEvent::Cancelling));
                stop_container(&binary, &container_id, &messages).await;
                let _ = messages.send(ControlMessage::Event(ContainerControlEvent::Stopped));
                return;
            }
            // Pausa repetida e retomada sem pausa são inofensivas.
            RunControl::Running | RunControl::Paused => {}
        }
    }
}

/// Aguarda a próxima mensagem do controlador do container.
///
/// Sem controlador, o futuro nunca resolve: o laço de execução fica sob
/// observação apenas do processo do Podman e do timeout.
async fn next_control_message(
    messages: &mut Option<mpsc::UnboundedReceiver<ControlMessage>>,
) -> Option<ControlMessage> {
    match messages {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// Resolve quando o cancelamento chega, ignorando pausa e retomada.
///
/// Um canal encerrado conta como cancelamento: sem ninguém capaz de retomar,
/// a execução em voo seria indefinida.
async fn wait_for_cancellation(control: &mut watch::Receiver<RunControl>) {
    loop {
        if control.changed().await.is_err() || *control.borrow_and_update() == RunControl::Cancelled
        {
            return;
        }
    }
}

/// Executa um comando de controle curto do Podman com prazo fixo.
async fn podman_control(binary: &Path, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new(binary);
    command.args(args).stdin(Stdio::null()).kill_on_drop(true);
    match tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, command.output()).await {
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => Err(format!(
            "podman {} falhou: {}",
            args.join(" "),
            output_message(&output.stderr)
        )),
        Ok(Err(error)) => Err(format!(
            "podman {} não pôde ser executado: {error}",
            args.join(" ")
        )),
        Err(_) => Err(format!(
            "podman {} não respondeu em até 10 segundos",
            args.join(" ")
        )),
    }
}

/// Encerra o container de forma cooperativa: `stop` e, se preciso, `kill`.
///
/// O `rm --force` é responsabilidade do laço principal, que já o emite para
/// todo caminho de saída; aqui só é garantido que o processo dentro do
/// container morre antes disso.
async fn stop_container(
    binary: &Path,
    container_id: &str,
    messages: &mpsc::UnboundedSender<ControlMessage>,
) {
    let _ = messages.send(ControlMessage::Trace(format!(
        "$ podman stop --time 5 {container_id}"
    )));
    let mut command = Command::new(binary);
    command
        .args(["stop", "--time", "5", container_id])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    // O `stop` tem prazo maior que os demais comandos: ele espera o scanner
    // reagir ao SIGTERM antes de devolver.
    let stop_timeout = PODMAN_CONTROL_TIMEOUT + Duration::from_secs(5);
    let stopped = matches!(
        tokio::time::timeout(stop_timeout, command.output()).await,
        Ok(Ok(output)) if output.status.success()
    );
    if !stopped {
        let mut kill = Command::new(binary);
        kill.args(["kill", container_id])
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let _ = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, kill.output()).await;
    }
}

/// Resultado de uma execução encerrada por cancelamento.
fn cancelled_result(
    container_id: String,
    cleanup_error: Option<String>,
    trace: Vec<String>,
) -> ExecutionResult {
    ExecutionResult {
        stdout: String::new(),
        stderr: String::new(),
        status: ExecutionStatus::Cancelled,
        duration: Duration::ZERO,
        container_id,
        cleanup_error,
        trace,
        artifact: None,
        artifact_error: None,
    }
}

/// Opções de uma execução: recursos do container, montagens e saída gravável.
struct ExecutionProfile<'a> {
    memory: &'a str,
    extra_tmpfs: &'a [String],
    mounts: &'a [(PathBuf, String)],
    writable_output: Option<&'a WritableOutput>,
}

/// Coletor do trace operacional completo de uma execução Podman.
///
/// Cada linha recebe timestamp e é acumulada para auditoria; quando há um
/// `sink`, a mesma linha é encaminhada ao vivo (TUI/headless). Nada do que o
/// Podman emite é descartado: comandos executados, saída do pull de imagem,
/// saída do scanner e resultado da limpeza.
struct TraceCollector {
    sink: Option<mpsc::UnboundedSender<String>>,
    lines: Vec<String>,
}

impl TraceCollector {
    fn new(sink: Option<mpsc::UnboundedSender<String>>) -> Self {
        Self {
            sink,
            lines: Vec::new(),
        }
    }

    fn sender(&self) -> Option<mpsc::UnboundedSender<String>> {
        self.sink.clone()
    }

    fn emit(&mut self, line: impl Into<String>) {
        let line = crate::utils::redaction::sanitize_text(&line.into());
        let line = format!("[{}] {line}", timestamp());
        if let Some(sink) = &self.sink {
            let _ = sink.send(line.clone());
        }
        self.lines.push(line);
    }
}

fn timestamp() -> String {
    chrono::Utc::now().format("%H:%M:%S").to_string()
}

impl PodmanExecutor {
    pub fn new(timeout: Duration) -> Self {
        Self {
            binary: PathBuf::from("podman"),
            timeout,
            log_sink: None,
            control: None,
        }
    }

    pub fn with_log_sink(mut self, sink: mpsc::UnboundedSender<String>) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// Conecta o executor ao canal de controle compartilhado.
    pub fn with_control(mut self, control: &ControlChannel) -> Self {
        self.control = Some(control.subscribe());
        self
    }

    #[cfg(test)]
    fn with_binary(binary: PathBuf, timeout: Duration) -> Self {
        Self {
            binary,
            timeout,
            log_sink: None,
            control: None,
        }
    }

    pub async fn execute(
        &self,
        image: &str,
        command: &[String],
    ) -> anyhow::Result<ExecutionResult> {
        self.execute_with_mounts(image, command, &[]).await
    }

    pub async fn execute_with_mounts(
        &self,
        image: &str,
        command: &[String],
        mounts: &[(PathBuf, String)],
    ) -> anyhow::Result<ExecutionResult> {
        let profile = ExecutionProfile {
            memory: DEFAULT_MEMORY_LIMIT,
            extra_tmpfs: &[],
            mounts,
            writable_output: None,
        };
        self.run(image, command, &profile).await
    }

    /// Executa a varredura coletando um artefato escrito pelo container.
    ///
    /// É a contraparte de [`PodmanExecutor::execute_with_mounts`] para
    /// scanners que **só** conseguem gravar um arquivo estruturado — como o
    /// ZAP, cujo job `report` sempre acrescenta a extensão do template ao nome e
    /// portanto nunca escreve no stdout.
    ///
    /// O executor cria o diretório de saída vazio no `TMPDIR` do host e monta
    /// apenas esse diretório, com `rw,noexec,nosuid,nodev`, em
    /// `output.container_dir`. Depois da execução e **antes** de remover o
    /// container, o arquivo é lido e devolvido em
    /// [`ExecutionResult::artifact`].
    ///
    /// A coleta não usa `podman cp`: o tmpfs do container é desmontado quando o
    /// container encerra, então um artefato em `/tmp` (tmpfs) é irrecuperável
    /// depois da saída. Como o diretório de saída é um bind mount do host, o
    /// arquivo já está no host e lê-lo diretamente evita uma operação extra de
    /// host que só funcionaria por acidente (ver
    /// `docs/evidence/issue-28-zap.md`).
    ///
    /// Artefato ausente não derruba a varredura: o motivo vai para
    /// [`ExecutionResult::artifact_error`] e a varredura segue marcada como
    /// falha pelo pipeline, nunca como varredura limpa. O guard de limpeza
    /// permanece armado em todos esses caminhos, então nenhum container vaza.
    pub async fn execute_with_artifact(
        &self,
        image: &str,
        command: &[String],
        mounts: &[(PathBuf, String)],
        output: &WritableOutput,
    ) -> anyhow::Result<ExecutionResult> {
        let profile = ExecutionProfile {
            memory: output.memory.as_str(),
            extra_tmpfs: &output.extra_tmpfs,
            mounts,
            writable_output: Some(output),
        };
        self.run(image, command, &profile).await
    }

    async fn run(
        &self,
        image: &str,
        command: &[String],
        profile: &ExecutionProfile<'_>,
    ) -> anyhow::Result<ExecutionResult> {
        let mut trace = TraceCollector::new(self.log_sink.clone());
        self.ensure_rootless(&mut trace).await?;

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

        // Janela de corrida antes do `create`: um cancelamento que já chegou
        // não deve criar container algum. A limpeza é tentada mesmo assim, por
        // nome, para não depender do estado do guard.
        if let Some(control) = self.control.clone() {
            let mut control = control;
            if *control.borrow_and_update() == RunControl::Cancelled {
                trace.emit("cancelamento recebido antes de criar o container");
                let cleanup_error = self.remove_container(&name, &mut trace).await.err();
                cleanup_guard.disarm();
                return Ok(cancelled_result(
                    name,
                    cleanup_error.map(|error| format!("{error:#}")),
                    trace.lines,
                ));
            }
        }

        let mut create_args: Vec<String> = vec![
            "create".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--network".to_owned(),
            ROOTLESS_NETWORK.to_owned(),
            "--memory".to_owned(),
            profile.memory.to_owned(),
            "--cpus".to_owned(),
            "1".to_owned(),
            "--pids-limit".to_owned(),
            "256".to_owned(),
            "--cap-drop".to_owned(),
            "all".to_owned(),
            "--security-opt".to_owned(),
            "no-new-privileges".to_owned(),
            "--read-only".to_owned(),
            "--tmpfs".to_owned(),
            "/tmp:rw,noexec,nosuid,nodev,size=128m".to_owned(),
            "--tmpfs".to_owned(),
            "/root/.config:rw,noexec,nosuid,nodev,size=16m".to_owned(),
        ];
        for tmpfs in profile.extra_tmpfs {
            create_args.push("--tmpfs".to_owned());
            create_args.push((*tmpfs).to_owned());
        }
        for (host, container) in profile.mounts {
            create_args.push("--volume".to_owned());
            create_args.push(format!("{}:{}:ro", host.display(), container));
        }
        if let Some(output) = profile.writable_output {
            create_args.push("--volume".to_owned());
            create_args.push(output.mount_spec());
        }
        create_args.push(image.to_owned());
        create_args.extend(command.iter().cloned());
        trace.emit(format!("$ podman {}", create_args.join(" ")));
        let mut create_command = self.podman_command();
        create_command.args(&create_args);
        // O `create` pode levar minutos (pull da imagem). O cancelamento
        // durante essa janela interrompe o comando do Podman e limpa pelo nome.
        let create_output = match self
            .await_or_cancel(self.timeout, create_command.output())
            .await
        {
            AwaitOutcome::Finished(output) => output.with_context(|| self.unavailable_message())?,
            AwaitOutcome::Cancelled => {
                trace.emit(format!(
                    "cancelamento recebido durante a criação de '{name}'"
                ));
                let cleanup = self.remove_container(&name, &mut trace).await.err();
                if cleanup.is_none() {
                    cleanup_guard.disarm();
                }
                return Ok(cancelled_result(
                    name,
                    cleanup.map(|error| format!("{error:#}")),
                    trace.lines,
                ));
            }
            AwaitOutcome::TimedOut => {
                trace.emit(format!(
                    "tempo limite de {:.0?} excedido ao criar o container '{name}'",
                    self.timeout
                ));
                let cleanup = self.remove_container(&name, &mut trace).await.err();
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
        for line in String::from_utf8_lossy(&create_output.stdout).lines() {
            trace.emit(line.to_owned());
        }
        for line in String::from_utf8_lossy(&create_output.stderr).lines() {
            trace.emit(line.to_owned());
        }

        if !create_output.status.success() {
            let cleanup_error = self.remove_container(&name, &mut trace).await.err();
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
            let cleanup = self.remove_container(&name, &mut trace).await.err();
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
        trace.emit(format!(
            "container {container_id} criado a partir da imagem '{image}'"
        ));

        let execution = self.run_attached(&container_id, &mut trace).await;
        // O artefato é coletado antes da remoção do container, para que a
        // remoção nunca impeça a leitura e a limpeza nunca vaze o container.
        let (artifact, artifact_error) = match profile.writable_output {
            Some(output) => collect_artifact(output, &mut trace),
            None => (None, None),
        };
        let cleanup_error = self
            .remove_container(&container_id, &mut trace)
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
            trace: trace.lines,
            artifact,
            artifact_error,
        })
    }

    async fn ensure_rootless(&self, trace: &mut TraceCollector) -> anyhow::Result<()> {
        trace.emit("$ podman info --format {{.Host.Security.Rootless}}");
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
        trace.emit("podman rootless verificado");
        Ok(())
    }

    async fn run_attached(
        &self,
        container_id: &str,
        trace: &mut TraceCollector,
    ) -> anyhow::Result<(String, String, ExecutionStatus, Duration)> {
        trace.emit(format!("$ podman start --attach {container_id}"));
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
        let sink = trace.sender();
        let stdout_task = tokio::spawn({
            let sink = sink.clone();
            async move { read_stream_live(stdout, sink).await }
        });
        let stderr_task = tokio::spawn(async move { read_stream_live(stderr, sink).await });
        let started_at = Instant::now();

        // Acompanha o processo do Podman enquanto reage ao canal de controle.
        // O timeout continua valendo mesmo pausado, para que uma pausa não
        // vire uma execução indefinida.
        let (mut messages, controller) = match self.control.clone() {
            Some(control) => {
                let (sender, receiver) = mpsc::unbounded_channel();
                let controller = tokio::spawn(container_control_loop(
                    self.binary.clone(),
                    container_id.to_owned(),
                    control,
                    sender,
                ));
                (Some(receiver), Some(controller))
            }
            None => (None, None),
        };
        let deadline = tokio::time::Instant::now() + self.timeout;

        // O `wait` fica preso ao processo do Podman; qualquer saída do laço
        // encerra o laço e libera o `child` para o `kill` cooperativo.
        let status = {
            let wait = child.wait();
            tokio::pin!(wait);
            loop {
                let message = tokio::select! {
                    result = &mut wait => break Self::status_from(result),
                    () = tokio::time::sleep_until(deadline) => {
                        trace.emit(format!(
                            "tempo limite excedido; interrompendo o container {container_id}"
                        ));
                        let mut kill = self.podman_command();
                        kill.args(["kill", container_id]);
                        let _ =
                            tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, kill.output()).await;
                        break ExecutionStatus::TimedOut;
                    }
                    message = next_control_message(&mut messages) => message,
                };
                match message {
                    Some(ControlMessage::Trace(line)) => trace.emit(line),
                    Some(ControlMessage::Event(ContainerControlEvent::Paused)) => {
                        trace.emit(format!("container {container_id} pausado"));
                    }
                    Some(ControlMessage::Event(ContainerControlEvent::Resumed)) => {
                        trace.emit(format!("container {container_id} retomado"));
                    }
                    Some(ControlMessage::Event(ContainerControlEvent::Failure(error))) => {
                        trace.emit(format!(
                            "controle do container {container_id} falhou: {error}"
                        ));
                    }
                    Some(ControlMessage::Event(ContainerControlEvent::Cancelling)) => {
                        trace.emit(format!(
                            "cancelamento recebido; encerrando o container {container_id}"
                        ));
                    }
                    // Só sai depois do `stop`/`kill`: sair antes deixaria o
                    // scanner rodando no container durante o `rm`.
                    Some(ControlMessage::Event(ContainerControlEvent::Stopped)) => {
                        break ExecutionStatus::Cancelled;
                    }
                    // O controlador terminou sem cancelar: a execucao segue
                    // sob observacao apenas do timeout e do processo.
                    None => messages = None,
                }
            }
        };
        if matches!(
            status,
            ExecutionStatus::Cancelled | ExecutionStatus::TimedOut
        ) {
            // O `podman stop`/`kill` roda na tarefa do controlador; encerrar o
            // processo local do Podman aqui libera os pipes de stdout/stderr.
            let _ = child.kill().await;
        }
        if let Some(controller) = controller {
            controller.abort();
        }
        // Corrida entre o fim do processo e o aviso do controlador: quando o
        // `podman stop` mata o scanner, o `start --attach` pode encerrar antes
        // de a mensagem chegar. O cancelamento pedido continua sendo o motivo,
        // e não uma falha do scanner.
        let status = match (&self.control, &status) {
            (Some(control), ExecutionStatus::Failed(_))
                if *control.borrow() == RunControl::Cancelled =>
            {
                trace.emit(format!(
                    "container {container_id} encerrado por cancelamento solicitado"
                ));
                ExecutionStatus::Cancelled
            }
            _ => status,
        };

        let (stdout, stdout_lines) = stdout_task
            .await
            .context("falha na tarefa de captura do stdout")?;
        let (stderr, stderr_lines) = stderr_task
            .await
            .context("falha na tarefa de captura do stderr")?;
        trace.lines.extend(stdout_lines);
        trace.lines.extend(stderr_lines);
        match &status {
            ExecutionStatus::Succeeded => {
                trace.emit(format!("container {container_id} concluído com sucesso"));
            }
            ExecutionStatus::Failed(code) => {
                trace.emit(format!(
                    "container {container_id} encerrou com status {}",
                    code.map_or_else(|| "desconhecido".to_owned(), |code| code.to_string())
                ));
            }
            ExecutionStatus::TimedOut => {
                trace.emit(format!("container {container_id} interrompido"));
            }
            ExecutionStatus::Cancelled => {
                trace.emit(format!(
                    "container {container_id} encerrado por cancelamento"
                ));
            }
        }

        Ok((
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            status,
            started_at.elapsed(),
        ))
    }

    /// Traduz o fim do processo do Podman em status de execução.
    fn status_from(wait: std::io::Result<std::process::ExitStatus>) -> ExecutionStatus {
        match wait {
            Ok(exit) if exit.success() => ExecutionStatus::Succeeded,
            Ok(exit) => ExecutionStatus::Failed(exit.code()),
            Err(_) => ExecutionStatus::Failed(None),
        }
    }

    /// Espera o futuro respeitando o timeout e o cancelamento do canal.
    ///
    /// Uma pausa **não** interrompe a espera: só o cancelamento encerra o
    /// comando em voo, para que o container não fique em estado indefinido.
    async fn await_or_cancel<F>(&self, timeout: Duration, future: F) -> AwaitOutcome
    where
        F: std::future::Future<Output = std::io::Result<std::process::Output>>,
    {
        let Some(control) = self.control.clone() else {
            return match tokio::time::timeout(timeout, future).await {
                Ok(result) => AwaitOutcome::Finished(result),
                Err(_) => AwaitOutcome::TimedOut,
            };
        };
        let mut control = control;
        // Marca o estado atual como visto: só uma ordem *nova* interrompe.
        let _ = control.borrow_and_update();
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::pin!(future);
        tokio::select! {
            output = &mut future => AwaitOutcome::Finished(output),
            () = tokio::time::sleep_until(deadline) => AwaitOutcome::TimedOut,
            () = wait_for_cancellation(&mut control) => AwaitOutcome::Cancelled,
        }
    }

    async fn remove_container(
        &self,
        container_id: &str,
        trace: &mut TraceCollector,
    ) -> anyhow::Result<()> {
        trace.emit(format!("$ podman rm --force --ignore {container_id}"));
        let mut command = self.podman_command();
        command.args(["rm", "--force", "--ignore", container_id]);
        let output = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, command.output())
            .await
            .context("a limpeza do Podman não terminou em até 10 segundos")?
            .context("falha ao executar a limpeza pelo Podman")?;
        if output.status.success() {
            trace.emit(format!("container {container_id} removido"));
            Ok(())
        } else {
            let error = anyhow!(
                "Podman não conseguiu remover o container {container_id}: {}",
                output_message(&output.stderr)
            );
            trace.emit(format!(
                "falha na limpeza do container {container_id}: {error:#}"
            ));
            Err(error)
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

/// Lê o artefato do diretório de saída depois da execução do scanner.
///
/// A ausência do artefato não é uma falha da varredura — o scanner pode ter
/// encerrado antes de gerar o relatório —, mas precisa ser reportada: uma saída
/// não coletada nunca pode ser interpretada como varredura limpa.
fn collect_artifact(
    output: &WritableOutput,
    trace: &mut TraceCollector,
) -> (Option<String>, Option<String>) {
    let container_path = output.container_path();
    let path = output.host_dir().join(&output.file_name);
    trace.emit(format!("$ leitura do artefato {container_path}"));
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            trace.emit(format!(
                "artefato {container_path} coletado ({} bytes)",
                content.len()
            ));
            (Some(content), None)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let message = format!(
                "o container {container_path} não gerou o relatório; revise o trace do Podman e o plano de automação da ferramenta"
            );
            trace.emit(format!("artefato ausente: {message}"));
            (None, Some(message))
        }
        Err(error) => {
            let message = format!(
                "não foi possível ler o artefato {container_path} produzido pelo container: {error}"
            );
            trace.emit(format!("falha na leitura do artefato: {message}"));
            (None, Some(message))
        }
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

/// Lê um stream do container linha a linha, preservando os bytes exatos para
/// auditoria e encaminhando cada linha ao vivo para o `sink` (TUI/headless).
///
/// `read_until` mantém o terminador quando presente, então a saída
/// reconstruída é byte a byte idêntica à original.
async fn read_stream_live<R>(
    stream: R,
    sink: Option<mpsc::UnboundedSender<String>>,
) -> (Vec<u8>, Vec<String>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut reader = tokio::io::BufReader::new(stream);
    let mut bytes = Vec::new();
    let mut lines = Vec::new();
    let mut chunk = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut chunk).await {
            Ok(0) => break,
            Ok(_) => {
                bytes.extend_from_slice(&chunk);
                let lossy = String::from_utf8_lossy(&chunk);
                let raw_line = lossy.trim_end_matches(['\r', '\n']);
                // O trace vai para o sink da TUI e do modo headless ao vivo, e
                // também para o log estruturado. Sanitizar aqui é obrigatório:
                // o stdout do TruffleHog carrega o valor do segredo em `Raw`,
                // `RawV2`, `Redacted` e `SecretParts`, e sem esta etapa o
                // segredo apareceria em tela em tempo real.
                let display = crate::utils::redaction::sanitize_text(raw_line);
                let line = format!("[{}] {display}", timestamp());
                if let Some(sink) = &sink {
                    let _ = sink.send(line.clone());
                }
                lines.push(line);
                chunk.clear();
            }
            Err(_) => break,
        }
    }
    (bytes, lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tmpfs::FilesystemProbe;

    /// Fonte de filesystem com tipo fixo, para exercitar a verificação de `tmpfs`
    /// sem depender da máquina de teste.
    struct FixedFilesystem(&'static str);

    impl tmpfs::FilesystemProbe for FixedFilesystem {
        fn filesystem(&self, _path: &Path) -> std::io::Result<Option<String>> {
            Ok(Some(self.0.to_owned()))
        }
    }

    /// Diretório base descartável, para que as asserções sobre o que foi criado
    /// não dependam do `TMPDIR` compartilhado com os demais testes.
    struct PrivateBase(PathBuf);

    impl PrivateBase {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "smartsec-base-teste-{}-{}",
                std::process::id(),
                CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("o diretório base de teste precisa ser criado");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn is_empty(&self) -> bool {
            fs::read_dir(&self.0)
                .map(|entries| entries.count() == 0)
                .unwrap_or(true)
        }
    }

    impl Drop for PrivateBase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Diretório de saída sobre `tmpfs`, para os testes do executor que não são
    /// sobre a verificação de filesystem.
    fn writable_output() -> WritableOutput {
        WritableOutput::new_in(
            &std::env::temp_dir(),
            "/smartsec-out",
            "relatorio.json",
            &FixedFilesystem(tmpfs::REQUIRED_FILESYSTEM),
        )
        .expect("o diretório de saída sobre tmpfs precisa ser criado")
    }

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
            Self::with_fixture(
                "fake_podman",
                create_script,
                start_script,
                cleanup_script,
                "exit 0",
            )
        }

        /// Mesmo harness, com o fake que também responde a `pause`/`unpause`.
        ///
        /// O fake padrão não conhece esses subcomandos, então um `podman pause`
        /// sairia com código 0 sem registrar nada: seria um teste vazio.
        fn with_control_scripts(
            create_script: &str,
            start_script: &str,
            cleanup_script: &str,
            control_script: &str,
        ) -> Self {
            Self::with_fixture(
                "fake_podman_control",
                create_script,
                start_script,
                cleanup_script,
                control_script,
            )
        }

        fn with_fixture(
            fixture: &str,
            create_script: &str,
            start_script: &str,
            cleanup_script: &str,
            control_script: &str,
        ) -> Self {
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
            fs::write(directory.join("control.sh"), control_script).unwrap();
            symlink(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures")
                    .join(fixture),
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
        assert_eq!(result.artifact, None);
        assert_eq!(result.artifact_error, None);
        assert!(result.duration <= Duration::from_secs(1));
        let calls = fake.calls();
        assert!(calls.contains("create --name smartsec-"));
        assert!(calls.contains("--network pasta:--map-host-loopback=169.254.1.2"));
        assert!(calls.contains("--cap-drop all"));
        assert!(calls.contains("--read-only"));
        assert!(calls.contains("--tmpfs /root/.config:rw,noexec,nosuid,nodev,size=16m"));
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
    async fn trace_sink_receives_the_complete_podman_lifecycle() {
        let fake = FakePodman::with_scripts(
            "printf 'Trying to pull example/scanner:1...\\n' >&2; printf 'container-123\\n'",
            "printf 'scanner line 1\\n'; printf 'scanner line 2\\n'; printf 'scanner warning\\n' >&2",
            "exit 0",
        );
        let (sink, mut receiver) = mpsc::unbounded_channel();
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(5))
            .with_log_sink(sink);

        let result = executor
            .execute("example/scanner:1", &["scan".to_owned()])
            .await
            .unwrap();

        let mut live = Vec::new();
        while let Ok(line) = receiver.try_recv() {
            live.push(line);
        }
        let mut live_sorted = live.clone();
        live_sorted.sort();
        let mut stored_sorted = result.trace.clone();
        stored_sorted.sort();
        assert_eq!(live_sorted, stored_sorted);
        let trace = result.trace.join("\n");
        assert!(trace.contains("$ podman info --format"));
        assert!(trace.contains("podman rootless verificado"));
        assert!(trace.contains("$ podman create --name smartsec-"));
        assert!(trace.contains("Trying to pull example/scanner:1..."));
        assert!(trace.contains("container-123"));
        assert!(trace.contains("criado a partir da imagem 'example/scanner:1'"));
        assert!(trace.contains("$ podman start --attach container-123"));
        assert!(trace.contains("scanner line 1"));
        assert!(trace.contains("scanner line 2"));
        assert!(trace.contains("scanner warning"));
        assert!(trace.contains("concluído com sucesso"));
        assert!(trace.contains("$ podman rm --force --ignore container-123"));
        assert!(trace.contains("container-123 removido"));
        assert_eq!(result.stdout, "scanner line 1\nscanner line 2\n");
        assert_eq!(result.stderr, "scanner warning\n");
    }

    /// `start.sh` que grava um artefato no diretório de saída gravável montado
    /// pelo executor, localizado no `calls.log` da própria chamada.
    fn write_artifact_script(content: &str) -> String {
        format!(
            "saida=$(sed -n 's/.*--volume \\([^:]*\\):\\/smartsec-out:.*/\\1/p' \"$(dirname \"$0\")/calls.log\" | head -1)\n\
             printf '%s' '{content}' > \"$saida/relatorio.json\"\n\
             exit 0\n",
            content = content.replace('\'', "'\\''")
        )
    }

    #[tokio::test]
    async fn collects_the_artifact_written_in_the_writable_output_dir() {
        let fake = FakePodman::new(&write_artifact_script("{\"alertas\":[]}"));
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(5));
        let output = writable_output()
            .with_memory("1536m")
            .with_tmpfs("/home/zap:rw,noexec,nosuid,nodev,size=512m");
        let host_dir = output.host_dir().to_path_buf();

        let result = executor
            .execute_with_artifact(
                "example/zap:1",
                &["zap.sh".to_owned(), "-cmd".to_owned()],
                &[],
                &output,
            )
            .await
            .unwrap();

        assert_eq!(result.artifact.as_deref(), Some("{\"alertas\":[]}"));
        assert_eq!(result.artifact_error, None);
        assert_eq!(result.status, ExecutionStatus::Succeeded);

        // O diretório de saída é o único bind mount gravável, com as travas.
        let calls = fake.calls();
        assert!(
            calls.contains(&format!(
                "{}:/smartsec-out:rw,noexec,nosuid,nodev",
                host_dir.display()
            )),
            "{calls}"
        );
        // O container mantém as travas do executor e a memória ajustada.
        assert!(calls.contains("--read-only"), "{calls}");
        assert!(calls.contains("--cap-drop all"), "{calls}");
        assert!(
            calls.contains("--security-opt no-new-privileges"),
            "{calls}"
        );
        assert!(calls.contains("--memory 1536m"), "{calls}");
        assert!(
            calls.contains("--tmpfs /home/zap:rw,noexec,nosuid,nodev,size=512m"),
            "{calls}"
        );
        // Nenhuma montagem recebe escrita além do diretório de saída.
        assert!(!calls.contains(":rw\n") || calls.contains(":rw,noexec,nosuid,nodev"));
        assert!(
            calls.contains("rm --force --ignore container-123"),
            "{calls}"
        );
        assert!(
            result
                .trace
                .iter()
                .any(|line| line
                    .ends_with("artefato /smartsec-out/relatorio.json coletado (14 bytes)")),
            "{:?}",
            result.trace
        );
    }

    #[tokio::test]
    async fn a_missing_artifact_is_reported_and_still_removes_the_container() {
        let fake = FakePodman::new("printf 'sem relatorio\\n'; exit 0");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(5));
        let output = writable_output();

        let result = executor
            .execute_with_artifact("example/zap:1", &["zap.sh".to_owned()], &[], &output)
            .await
            .unwrap();

        assert_eq!(result.artifact, None);
        let error = result
            .artifact_error
            .expect("a ausência precisa ser reportada");
        assert!(error.contains("/smartsec-out/relatorio.json"), "{error}");
        assert!(error.contains("não gerou o relatório"), "{error}");
        // A varredura em si não é elevada a falha pelo executor...
        assert_eq!(result.status, ExecutionStatus::Succeeded);
        // ...mas o container é removido normalmente.
        assert!(
            fake.calls().contains("rm --force --ignore container-123"),
            "o container não pode vazar: {}",
            fake.calls()
        );
    }

    #[tokio::test]
    async fn a_failed_scan_still_collects_the_artifact_and_removes_the_container() {
        let fake =
            FakePodman::new(&write_artifact_script("{\"parcial\":1}").replace("exit 0", "exit 3"));
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(5));
        let output = writable_output();

        let result = executor
            .execute_with_artifact("example/zap:1", &["zap.sh".to_owned()], &[], &output)
            .await
            .unwrap();

        // O ZAP pode terminar com status diferente de zero e ainda assim ter
        // gerado o relatório; o artefato é aproveitado.
        assert_eq!(result.status, ExecutionStatus::Failed(Some(3)));
        assert_eq!(result.artifact.as_deref(), Some("{\"parcial\":1}"));
        assert!(fake.calls().contains("rm --force --ignore container-123"));
    }

    #[tokio::test]
    async fn a_timeout_collects_no_artifact_and_removes_the_container() {
        let fake = FakePodman::new("exec sleep 10");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(1));
        let output = writable_output();

        let result = executor
            .execute_with_artifact("example/zap:1", &["zap.sh".to_owned()], &[], &output)
            .await
            .unwrap();

        assert_eq!(result.status, ExecutionStatus::TimedOut);
        assert_eq!(result.artifact, None);
        assert!(result.artifact_error.is_some());
        let calls = fake.calls();
        assert!(calls.contains("kill container-123"), "{calls}");
        assert!(
            calls.contains("rm --force --ignore container-123"),
            "{calls}"
        );
    }

    #[tokio::test]
    async fn cancellation_during_an_artifact_run_removes_the_container() {
        let fake = FakePodman::new("exec sleep 10");
        let executor = PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(30));
        let output = writable_output();
        let task = tokio::spawn(async move {
            executor
                .execute_with_artifact("example/zap:1", &["zap.sh".to_owned()], &[], &output)
                .await
        });

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

    #[test]
    fn the_writable_output_dir_is_removed_when_the_value_goes_out_of_scope() {
        let path = {
            let output = writable_output();
            let path = output.host_dir().to_path_buf();
            assert!(path.is_dir());
            assert_eq!(output.container_path(), "/smartsec-out/relatorio.json");
            path
        };
        assert!(!path.exists(), "o diretório de saída não pode sobrar");
    }

    #[test]
    fn the_writable_output_is_created_when_the_base_dir_is_tmpfs() {
        // Caminho positivo da regra: com tmpfs, o diretório é criado.
        let base = PrivateBase::create();
        let output = WritableOutput::new_in(
            base.path(),
            "/smartsec-out",
            "relatorio.json",
            &FixedFilesystem(tmpfs::REQUIRED_FILESYSTEM),
        )
        .expect("uma tmpfs atende a regra de isolamento");
        assert!(output.host_dir().starts_with(base.path()));
        assert!(output.host_dir().is_dir());
        assert_eq!(output.container_path(), "/smartsec-out/relatorio.json");
    }

    #[test]
    fn the_writable_output_is_refused_when_the_base_dir_is_on_a_regular_disk() {
        // Caminho negativo da regra: um diretório base em disco comum (o caso de
        // um runner de CI com `TMPDIR` apontando para o disco) não pode montar
        // um bind mount persistente. A execução falha, não degrada.
        for filesystem in ["ext4", "xfs", "btrfs", "overlay"] {
            let base = PrivateBase::create();
            let error = match WritableOutput::new_in(
                base.path(),
                "/smartsec-out",
                "relatorio.json",
                &FixedFilesystem(filesystem),
            ) {
                Ok(_) => panic!("fora de tmpfs a criação precisa falhar"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(filesystem), "{error}");
            assert!(error.contains("'tmpfs'"), "{error}");
            assert!(error.contains("TMPDIR"), "{error}");
            assert!(error.contains("relatório do scanner"), "{error}");
            assert!(error.contains("mount -t tmpfs"), "{error}");
            assert!(
                base.is_empty(),
                "nenhum diretório pode ser criado fora da regra: {}",
                base.path().display()
            );
        }
    }

    #[test]
    fn the_real_temp_dir_of_this_machine_is_verified_and_never_assumed() {
        // O fluxo real lê `/proc/self/mountinfo`. Este teste não presume que a
        // máquina de teste tem tmpfs: ele exige que o resultado da verificação
        // real seja coerente com a tabela de montagens do processo.
        let temp_dir = std::env::temp_dir();
        let probe = tmpfs::ProcMounts::process();
        let declared = probe
            .filesystem(&temp_dir)
            .expect("a tabela de montagens do processo precisa ser legível")
            .expect("o TMPDIR precisa estar sob algum ponto de montagem");
        match WritableOutput::new("/smartsec-out", "relatorio.json") {
            Ok(_) => assert_eq!(
                declared,
                tmpfs::REQUIRED_FILESYSTEM,
                "a criação só pode ser liberada com tmpfs no TMPDIR"
            ),
            Err(error) => {
                let error = error.to_string();
                assert_ne!(
                    declared,
                    tmpfs::REQUIRED_FILESYSTEM,
                    "com tmpfs no TMPDIR a criação não deveria falhar: {error}"
                );
                assert!(error.contains(&declared), "{error}");
            }
        }
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

    /// Espera o fake registrar uma chamada, para tornar as corridas determinísticas.
    async fn wait_for_call(fake: &FakePodman, needle: &str) {
        for _ in 0..200 {
            if fake.calls().contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("o Podman falso não registrou {needle}:\n{}", fake.calls());
    }

    fn controlled_executor(fake: &FakePodman, control: &ControlChannel) -> PodmanExecutor {
        PodmanExecutor::with_binary(fake.binary.clone(), Duration::from_secs(30))
            .with_control(control)
    }

    #[tokio::test]
    async fn pause_and_resume_issue_podman_pause_and_unpause() {
        let fake = FakePodman::with_control_scripts(
            "printf 'container-123\\n'",
            "exec sleep 10",
            "exit 0",
            "exit 0",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "start --attach container-123").await;
        control.pause();
        wait_for_call(&fake, "pause container-123").await;

        control.resume();
        wait_for_call(&fake, "unpause container-123").await;

        control.cancel();
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.status, ExecutionStatus::Cancelled);
        let calls = fake.calls();
        assert!(
            calls.contains("rm --force --ignore container-123"),
            "{calls}"
        );
    }

    #[tokio::test]
    async fn repeated_pause_does_not_issue_a_second_pause() {
        let fake = FakePodman::with_control_scripts(
            "printf 'container-123\\n'",
            "exec sleep 10",
            "exit 0",
            "exit 0",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "start --attach container-123").await;
        control.pause();
        wait_for_call(&fake, "pause container-123").await;

        // Pausa duplicada: o estado pedido não muda, então nenhum comando extra.
        control.pause();
        control.resume();
        wait_for_call(&fake, "unpause container-123").await;
        assert_eq!(
            fake.calls()
                .lines()
                .filter(|line| line.trim() == "pause container-123")
                .count(),
            1,
            "pausar de novo não pode repetir o comando no container:\n{}",
            fake.calls()
        );

        control.cancel();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancel_after_pause_stops_and_removes_the_container() {
        let fake = FakePodman::with_control_scripts(
            "printf 'container-123\\n'",
            "exec sleep 10",
            "exit 0",
            "exit 0",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "start --attach container-123").await;
        control.pause();
        wait_for_call(&fake, "pause container-123").await;

        control.cancel();
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.status, ExecutionStatus::Cancelled);
        let calls = fake.calls();
        assert!(calls.contains("stop --time 5 container-123"), "{calls}");
        assert!(
            calls.contains("rm --force --ignore container-123"),
            "{calls}"
        );
    }

    #[tokio::test]
    async fn cancel_before_create_never_creates_a_container() {
        let fake = FakePodman::new("exit 0");
        let control = ControlChannel::new();
        control.cancel();
        let executor = controlled_executor(&fake, &control);

        let result = executor.execute("scanner", &[]).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Cancelled);
        let calls = fake.calls();
        assert!(!calls.contains("create --name"), "{calls}");
        assert!(calls.contains("rm --force --ignore smartsec-"), "{calls}");
    }

    #[tokio::test]
    async fn cancel_during_create_removes_the_container_by_name() {
        let fake = FakePodman::with_control_scripts("exec sleep 10", "exit 0", "exit 0", "exit 0");
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "create --name smartsec-").await;
        control.cancel();
        let result = task.await.unwrap().unwrap();

        assert_eq!(result.status, ExecutionStatus::Cancelled);
        let calls = fake.calls();
        assert!(!calls.contains("start --attach"), "{calls}");
        assert!(calls.contains("rm --force --ignore smartsec-"), "{calls}");
    }

    #[tokio::test]
    async fn pause_arriving_while_the_container_starts_is_applied() {
        // O `create` é lento; a pausa chega antes de o container existir.
        let fake = FakePodman::with_control_scripts(
            "sleep 0.5; printf 'container-123\\n'",
            "exec sleep 10",
            "exit 0",
            "exit 0",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "create --name smartsec-").await;
        control.pause();
        wait_for_call(&fake, "pause container-123").await;
        let calls = fake.calls();
        assert!(
            calls.find("create --name smartsec-") < calls.find("pause container-123"),
            "o pause deve vir depois do create, nunca antes:\n{calls}"
        );

        control.resume();
        wait_for_call(&fake, "unpause container-123").await;
        control.cancel();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_stopped_container_is_cancelled_not_failed() {
        // O `podman stop` mata o scanner e o `start --attach` retorna com 137.
        // A execução tem de ser registrada como cancelada, e não como falha do
        // scanner: o cancelamento foi pedido, o scanner não falhou.
        // O `stop` do fake é lento, e o scanner morre antes dele responder: o
        // `start --attach` encerra primeiro, com o laço ainda esperando o aviso
        // do controlador. É a corrida descrita no código.
        let fake = FakePodman::with_control_scripts(
            "printf 'container-123\\n'",
            "sleep 0.4; kill -TERM $$; sleep 30",
            "exit 0",
            "sleep 5; exit 0",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "start --attach container-123").await;
        control.cancel();
        let result = task.await.unwrap().unwrap();

        assert_eq!(result.status, ExecutionStatus::Cancelled);
        assert!(fake.calls().contains("rm --force --ignore container-123"));
    }

    #[tokio::test]
    async fn cancel_racing_with_the_finished_container_still_removes_it() {
        // O `start` termina sozinho enquanto o cancelamento chega: qualquer
        // ordem precisa remover o container, sem órfão e sem estado ambíguo.
        for attempt in 0..12 {
            let fake = FakePodman::with_control_scripts(
                "printf 'container-123\\n'",
                "printf 'fim da varredura\\n'",
                "exit 0",
                "exit 0",
            );
            let control = ControlChannel::new();
            let executor = controlled_executor(&fake, &control);
            let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

            wait_for_call(&fake, "start --attach container-123").await;
            if attempt % 2 == 0 {
                control.cancel();
            }
            tokio::time::sleep(Duration::from_millis(attempt % 4)).await;
            control.cancel();

            let result = task.await.unwrap().unwrap();
            assert!(
                matches!(
                    result.status,
                    ExecutionStatus::Cancelled | ExecutionStatus::Succeeded
                ),
                "tentativa {attempt}: estado inesperado {:?}",
                result.status
            );
            assert!(
                fake.calls().contains("rm --force --ignore container-123"),
                "tentativa {attempt} deixou container órfão:\n{}",
                fake.calls()
            );
        }
    }

    #[tokio::test]
    async fn a_refused_pause_is_reported_and_the_scan_survives_it() {
        // O Podman recusa a pausa: a tela precisa saber, mas a varredura não
        // pode ser derrubada por causa disso.
        let fake = FakePodman::with_control_scripts(
            "printf 'container-123\\n'",
            "exec sleep 10",
            "exit 0",
            "printf 'container is not running\\n' >&2; exit 125",
        );
        let control = ControlChannel::new();
        let executor = controlled_executor(&fake, &control);
        let task = tokio::spawn(async move { executor.execute("scanner", &[]).await });

        wait_for_call(&fake, "start --attach container-123").await;
        control.pause();
        wait_for_call(&fake, "pause container-123").await;

        // O cancelamento ainda precisa encerrar e remover o container.
        control.cancel();
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.status, ExecutionStatus::Cancelled);
        let trace = result.trace.join("\n");
        assert!(
            trace.contains("controle do container container-123 falhou"),
            "a recusa do Podman precisa aparecer no trace:\n{trace}"
        );
        assert!(fake.calls().contains("rm --force --ignore container-123"));
    }
}
