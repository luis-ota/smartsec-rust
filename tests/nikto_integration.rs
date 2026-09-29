//! Teste de integração do fluxo do Nikto com o Podman rootless.
//!
//! O binário `podman` é substituído pelo fake de `tests/fixtures/fake_podman`,
//! que reproduz o ciclo completo do executor (info, create, start, rm) sem
//! executar qualquer container real. Isso valida o caminho do SmartSec de ponta
//! a ponta — manifesto, runner, parser e log estruturado — sem rede e sem
//! privilégios.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RELATORIO_NIKTO: &str = include_str!("fixtures/nikto/relatorio.json");
const SEM_SERVIDOR: &str = include_str!("fixtures/nikto/sem_servidor.json");

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
            "smartsec-nikto-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("bin")).expect("o sandbox deve ser criado");
        Self { root }
    }

    /// Instala o fake do Podman no PATH do processo filho.
    fn install_fake_podman(&self) -> PathBuf {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let target = self.root.join("bin").join("podman");
        std::os::unix::fs::symlink(manifest_dir.join("tests/fixtures/fake_podman"), &target)
            .expect("o symlink do fake podman deve ser criado");
        target
    }

    /// Grava um script que o fake do Podman executa.
    ///
    /// O fake resolve `create.sh`, `start.sh` e `cleanup.sh` em
    /// `dirname "$0"`, que é o diretório do symlink criado em `bin/`.
    fn write_script(&self, name: &str, script: &str) {
        std::fs::write(self.root.join("bin").join(name), script)
            .expect("o script do fake podman deve ser escrito");
    }

    /// Configura o ciclo completo do fake para emitir `report` no stdout.
    ///
    /// O conteúdo é gravado em um arquivo e impresso com `cat`, evitando
    /// interpolar JSON dentro de um script `sh`.
    fn emit_report(&self, report: &str) {
        let report_path = self.root.join("bin").join("nikto-report.json");
        std::fs::write(&report_path, report).expect("o relatório deve ser escrito");
        self.install_scripts(&format!("cat '{}'; exit 0", report_path.display()));
    }

    /// Configura o ciclo completo do fake: create, start e cleanup.
    fn install_scripts(&self, start: &str) {
        self.write_script("create.sh", "printf 'container-123\n'");
        self.write_script("start.sh", start);
        self.write_script("cleanup.sh", "exit 0");
    }

    /// Invoca o binário do SmartSec com o Podman fake no PATH.
    fn run(&self, extra_path: &Path, args: &[&str]) -> std::process::Output {
        let path = format!(
            "{}:{}",
            extra_path.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new(env!("CARGO_BIN_EXE_smartsec-rust"))
            .args(args)
            .env("PATH", path)
            .env("XDG_CONFIG_HOME", &self.root)
            .env("HOME", &self.root)
            .current_dir(&self.root)
            .output()
            .expect("o binário do SmartSec deve ser executável")
    }

    /// O fake do Podman grava o log em `dirname "$0"`, que é o diretório do
    /// symlink criado em `bin/`.
    fn calls(&self) -> String {
        std::fs::read_to_string(self.root.join("bin").join("calls.log")).unwrap_or_default()
    }

    /// Conteúdo do log estruturado gravado pelo SmartSec.
    fn latest_scan_log(&self) -> String {
        let scans = self.root.join("smartsec").join("scans");
        let Ok(entries) = std::fs::read_dir(&scans) else {
            return String::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        paths
            .last()
            .map(|path| std::fs::read_to_string(path).unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// O alvo é sempre o loopback do sandbox local: o teste não alcança a rede.
const TARGET: &str = "http://127.0.0.1:3000";

#[test]
fn nikto_is_selectable_in_the_headless_run_and_records_image_and_version() {
    let sandbox = Sandbox::new("catalogo");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_NIKTO);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "Nikto", "--target", TARGET],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "o fluxo do Nikto deveria concluir.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // A imagem fixada e o comando sem shell chegam ao container.
    let calls = sandbox.calls();
    assert!(calls.contains("nikto"), "{calls}");
    assert!(
        calls.contains("docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b"),
        "{calls}"
    );
    // O container é criado com as travas de segurança do executor.
    assert!(calls.contains("--cap-drop all"), "{calls}");
    assert!(calls.contains("--read-only"), "{calls}");
    assert!(
        calls.contains("pasta:--map-host-loopback=169.254.1.2"),
        "{calls}"
    );
    // Nenhum item do comando vira opção do Podman nem passa por shell.
    assert!(!calls.contains("--privileged"), "{calls}");
    assert!(!calls.contains("; sh "), "{calls}");
    // O container é removido ao final.
    assert!(
        calls.contains("rm --force --ignore container-123"),
        "{calls}"
    );
}

#[test]
fn nikto_findings_reach_the_structured_log_with_url_method_and_reference() {
    let sandbox = Sandbox::new("achados");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_NIKTO);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "Nikto",
            "--target",
            TARGET,
            "--output",
            "relatorio.json",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");

    let report = std::fs::read_to_string(sandbox.root.join("relatorio.json"))
        .expect("o relatório Markdown deve ser gravado");
    // O relatório apresenta os achados do Nikto com proveniência real.
    assert!(report.contains("Nikto"), "{report}");
    assert!(report.contains("999957"), "{report}");

    let scan_log = sandbox.latest_scan_log();
    assert!(!scan_log.is_empty(), "o log estruturado deve existir");
    // Imagem e versão registradas no log estruturado (RNF09).
    assert!(
        scan_log.contains("docker.io/alpine/nikto:2.2.0@sha256:eb2fe88217ec32695f3843f67c7a7f1628b484b653e99015aac69c586eb2a88b"),
        "{scan_log}"
    );
    assert!(scan_log.contains("2.1.6"), "{scan_log}");
    // Evidência mínima: URL, método e referência preservados, sem corpo HTTP.
    assert!(
        scan_log.contains("url: http://127.0.0.1:3000/"),
        "{scan_log}"
    );
    assert!(scan_log.contains("método: GET"), "{scan_log}");
    assert!(scan_log.contains("referência: nikto:999957"), "{scan_log}");
    assert!(!scan_log.contains("segredo"), "{scan_log}");
}

#[test]
fn a_nikto_run_without_a_web_server_fails_with_an_actionable_message() {
    let sandbox = Sandbox::new("sem-servidor");
    let bin = sandbox.install_fake_podman();
    // O Nikto termina com exit status 0 mesmo sem encontrar servidor web.
    sandbox.emit_report(SEM_SERVIDOR);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "Nikto", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Sem servidor web não há achado: o run é marcado como falha acionável.
    assert!(
        combined.contains("não encontrou servidor web") || combined.contains("não encontrou"),
        "a falha precisa ser explicada em pt-BR.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !output.status.success(),
        "uma varredura sem servidor web não deve ser considerada sucesso.\nstdout: {stdout}"
    );
}

#[test]
fn a_nikto_nonzero_exit_status_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("exit-status");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf 'erro interno do scanner' >&2; exit 7");

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "Nikto", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined.contains("status 7") || combined.contains("7"),
        "o exit status do container precisa aparecer.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // O container é removido mesmo com falha.
    assert!(sandbox
        .calls()
        .contains("rm --force --ignore container-123"));
}

#[test]
fn invalid_nikto_output_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("invalido");
    let bin = sandbox.install_fake_podman();
    // Saída truncada: o container encerra com status 0, mas o stdout não é um
    // relatório JSON válido.
    sandbox.install_scripts("printf '{\"host\":\"alvo\",\"vulnerabilities\":['; exit 0");

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "Nikto", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !output.status.success(),
        "saída inválida não pode virar varredura limpa.\nstdout: {stdout}"
    );
    assert!(
        combined.contains("JSON do Nikto inválido")
            || combined.contains("não produziu relatório JSON"),
        "a saída inválida precisa ser reportada.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn nmap_and_nuclei_keep_working_alongside_the_nikto_integration() {
    let sandbox = Sandbox::new("regressao");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf '<nmaprun></nmaprun>'; exit 0");

    // O catálogo embutido continua aceitando as três ferramentas.
    for tool in ["Nmap", "Nuclei", "Nikto"] {
        let output = sandbox.run(bin.parent().unwrap(), &["tool", tool, "--target", TARGET]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("ferramenta desconhecida"),
            "{tool} deveria estar no catálogo.\nstderr: {stderr}"
        );
    }
}
