//! Cancelamento por sinal do sistema no modo headless (issue #21, REQ14).
//!
//! O teste executa o binário real, envia SIGINT e SIGTERM e verifica o que a
//! seção 10 do `TCC_SPEC.md` exige: exit code de cancelamento, relatório e log
//! estruturado gravados **antes** da saída, e nenhum container órfão.
//!
//! O Podman é substituído pelo fake do repositório, de modo que o teste não
//! depende de rede nem de imagens reais. O fake **não** é modificado: este
//! teste apenas o coloca no `PATH` do processo filho.

use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EXIT_SIGINT: i32 = 130;
const EXIT_SIGTERM: i32 = 143;

/// Diretório isolado com o Podman falso, o `HOME` e a configuração.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "smartsec-sinal-{label}-{}-{unique}",
            std::process::id()
        ));
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).expect("o diretório isolado deve ser criado");
        symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_podman"),
            bin.join("podman"),
        )
        .expect("o symlink do Podman falso deve ser criado");
        // O fake resolve os scripts por `dirname $0`, ou seja, ao lado do
        // próprio symlink. O `start` segura a execução por tempo suficiente
        // para o sinal chegar enquanto o container está em execução.
        //
        // O `exec` importa: sem ele o `sleep` sobreviveria ao `kill` do
        // processo do Podman, e o leitor de stdout ficaria aberto até o fim da
        // espera. Com o `exec`, o sinal alcança o processo que realmente está
        // segurando o stdout, como acontece com `podman start --attach`.
        std::fs::write(bin.join("create.sh"), "printf 'container-fake-1\\n'").unwrap();
        std::fs::write(
            bin.join("start.sh"),
            "printf 'scanner rodando\\n'; exec sleep 30",
        )
        .unwrap();
        std::fs::write(bin.join("cleanup.sh"), "exit 0").unwrap();
        std::fs::write(
            root.join("smartsec.toml"),
            "target_url = \"http://192.0.2.10\"\n\
             active_tools = [\"ScannerExemplo\"]\n\
             output_file = \"relatorio.md\"\n\
             \n[llm]\nprovider = \"Ollama\"\nbase_url = \"http://127.0.0.1:1/v1\"\nmodel = \"local\"\n\
             \n[[tools]]\nname = \"ScannerExemplo\"\ndescription = \"Scanner de servidores web\"\ncategory = \"DAST\"\n\
             image = \"example/zap:1\"\nversion = \"1.0\"\nrunner = \"generic\"\nparser = \"generic-text\"\n\
             command_template = [\"zap\", \"-host\", \"{target}\"]\noutput_format = \"text\"\n",
        )
        .unwrap();
        Self { root }
    }

    fn podman_calls(&self) -> String {
        std::fs::read_to_string(self.root.join("bin/calls.log")).unwrap_or_default()
    }

    fn report(&self) -> PathBuf {
        self.root.join("relatorio.md")
    }

    /// Diretório de scans estruturados gravados sob o `HOME` isolado.
    fn scans_dir(&self) -> PathBuf {
        self.root.join(".config/smartsec/scans")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"));
        command
            .env("XDG_CONFIG_HOME", self.root.join(".config"))
            .env("HOME", &self.root)
            // O Podman falso precisa vir primeiro; nada mais de Podman é usado.
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .current_dir(&self.root)
            .args(["scan", "--target", "192.0.2.10"])
            .arg("--config")
            .arg(self.root.join("smartsec.toml"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Inicia a varredura e espera o container entrar em execução.
    fn start_and_wait_for_container(&self) -> Running {
        let child = self
            .command()
            .spawn()
            .expect("o binário do SmartSec deve iniciar");
        let mut running = Running { child };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.podman_calls().contains("start --attach") {
                return running;
            }
            if let Some(status) = running.try_wait() {
                panic!(
                    "o processo terminou antes de iniciar o container (status {status:?})\n{}",
                    running.take_output()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "o container não começou a executar a tempo:\n{}",
            self.podman_calls()
        );
    }

    fn send_signal(&self, child: &Running, signal: &str) {
        let status = Command::new("kill")
            .args(["-s", signal, &child.id().to_string()])
            .status()
            .expect("o comando kill precisa estar disponível");
        assert!(status.success(), "falha ao enviar {signal}");
    }

    /// Verifica o contrato do §10 do TCC_SPEC para o caminho de cancelamento.
    fn assert_cancel_contract(&self, child: &mut Running, expected_code: i32, signal: &str) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait() {
                break status;
            }
            if Instant::now() > deadline {
                panic!("o processo não saiu após {signal}");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let output = child.take_output();

        assert_eq!(
            status.code(),
            Some(expected_code),
            "exit code de cancelamento por {signal} incorreto\n{output}"
        );
        assert!(
            output.contains(signal),
            "a saída precisa nomear o sinal que cancelou a varredura\n{output}"
        );

        // O relatório e o log estruturado são gravados antes da mensagem final.
        assert!(
            self.report().exists(),
            "o relatório precisa existir mesmo cancelado\n{output}"
        );
        let logs: Vec<_> = std::fs::read_dir(self.scans_dir())
            .expect("o diretório de scans precisa existir")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .collect();
        assert_eq!(logs.len(), 1, "esperado exatamente um log estruturado");
        let log = std::fs::read_to_string(logs[0].path()).expect("o log precisa ser legível");
        assert!(
            log.contains("cancelado_por_sinal"),
            "o motivo do cancelamento precisa ser auditável\n{log}"
        );
        assert!(
            log.contains(signal),
            "o sinal precisa constar no log\n{log}"
        );

        // Nenhum container órfão: o executor emitiu o `rm` e ele conclusionou.
        let calls = self.podman_calls();
        assert!(
            calls.contains("rm --force --ignore container-fake-1"),
            "o container deveria ter sido removido\n{calls}"
        );
        assert!(
            !calls.contains("create --name") || calls.contains("rm --force --ignore"),
            "não pode haver container criado sem remoção\n{calls}"
        );
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Processo filho guardado: garante `wait()` em todos os caminhos, inclusive
/// quando o teste falha antes de chegar ao cancelamento.
struct Running {
    child: Child,
}

impl Running {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("estado do processo filho")
    }

    fn take_output(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut stdout) = self.child.stdout.take() {
            let _ = stdout.read_to_string(&mut text);
        }
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut text);
        }
        text
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Só mata se o processo ainda estiver vivo; um processo já encerrado é
        // apenas aguardado, para não deixar zumbi.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn sigint_cancels_the_scan_keeps_the_artifacts_and_leaves_no_container() {
    let sandbox = Sandbox::new("sigint");
    let mut child = sandbox.start_and_wait_for_container();

    sandbox.send_signal(&child, "INT");

    sandbox.assert_cancel_contract(&mut child, EXIT_SIGINT, "SIGINT");
}

#[test]
fn sigterm_cancels_the_scan_keeps_the_artifacts_and_leaves_no_container() {
    let sandbox = Sandbox::new("sigterm");
    let mut child = sandbox.start_and_wait_for_container();

    sandbox.send_signal(&child, "TERM");

    sandbox.assert_cancel_contract(&mut child, EXIT_SIGTERM, "SIGTERM");
}

#[test]
fn the_help_text_documents_the_cancellation_exit_codes() {
    let output = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"))
        .arg("--help")
        .output()
        .expect("o binário deve responder a --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("130"),
        "130 precisa estar documentado\n{stdout}"
    );
    assert!(
        stdout.contains("143"),
        "143 precisa estar documentado\n{stdout}"
    );
    assert!(stdout.contains("SIGINT"), "{stdout}");
    assert!(stdout.contains("SIGTERM"), "{stdout}");
    assert!(
        stdout.contains("--max-critical-findings"),
        "a regra automática precisa estar documentada\n{stdout}"
    );
}
