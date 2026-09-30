use crate::orchestrator::tmpfs;
use anyhow::{anyhow, Context};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;

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
        }
    }

    pub fn with_log_sink(mut self, sink: mpsc::UnboundedSender<String>) -> Self {
        self.log_sink = Some(sink);
        self
    }

    #[cfg(test)]
    fn with_binary(binary: PathBuf, timeout: Duration) -> Self {
        Self {
            binary,
            timeout,
            log_sink: None,
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
        let create_output = match tokio::time::timeout(self.timeout, create_command.output()).await
        {
            Ok(output) => output.with_context(|| self.unavailable_message())?,
            Err(_) => {
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
                trace.emit(format!(
                    "tempo limite excedido; interrompendo o container {container_id}"
                ));
                let _ = child.kill().await;
                let mut kill_command = self.podman_command();
                kill_command.args(["kill", container_id]);
                let _ = tokio::time::timeout(PODMAN_CONTROL_TIMEOUT, kill_command.output()).await;
                ExecutionStatus::TimedOut
            }
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
        }

        Ok((
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
            status,
            started_at.elapsed(),
        ))
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
                let display = String::from_utf8_lossy(&chunk);
                let display = display.trim_end_matches(['\r', '\n']);
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
}
