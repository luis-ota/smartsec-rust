//! Teste de integração do fluxo do OWASP ZAP com o Podman rootless.
//!
//! O binário `podman` é substituído pelo fake paralelo
//! `tests/fixtures/fake_podman_zap`, que reproduz o ciclo do executor
//! (info, create, start, rm) e grava o relatório no diretório de saída
//! gravável que o executor monta. O fake compartilhado
//! `tests/fixtures/fake_podman` não é alterado, porque outros fluxos o usam.
//! Isso valida o caminho do SmartSec de ponta a ponta — manifesto, runner,
//! coleta do artefato, parser e log estruturado — sem rede e sem privilégios.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RELATORIO_ZAP: &str = include_str!("fixtures/zap/relatorio.json");
const INVALIDO: &str = include_str!("fixtures/zap/invalido.json");

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
            "smartsec-zap-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("bin")).expect("o sandbox deve ser criado");
        Self { root }
    }

    /// Instala o fake do Podman no PATH do processo filho.
    fn install_fake_podman(&self) -> PathBuf {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let target = self.root.join("bin").join("podman");
        std::os::unix::fs::symlink(manifest_dir.join("tests/fixtures/fake_podman_zap"), &target)
            .expect("o symlink do fake podman deve ser criado");
        target
    }

    fn write_script(&self, name: &str, script: &str) {
        std::fs::write(self.root.join("bin").join(name), script)
            .expect("o script do fake podman deve ser escrito");
    }

    /// Configura o ciclo completo do fake: create, start e cleanup.
    fn install_scripts(&self, start: &str) {
        self.write_script("create.sh", "printf 'container-123\n'");
        self.write_script("start.sh", start);
        self.write_script("cleanup.sh", "exit 0");
    }

    /// Grava o relatório que o ZAP produziria no diretório de saída.
    ///
    /// O conteúdo vai para um arquivo e é copiado por `cat`, evitando interpolar
    /// JSON dentro de um script `sh`. O diretório montado em `/smartsec-out` é
    /// deduzido da chamada `create` registrada pelo fake.
    fn emit_report(&self, report: &str) {
        let report_path = self.root.join("bin").join("zap-report.json");
        std::fs::write(&report_path, report).expect("o relatório deve ser escrito");
        self.install_scripts(&format!(
            "saida=$(sed -n 's/.*--volume \\([^:]*\\):\\/smartsec-out:.*/\\1/p' \"$(dirname \"$0\")/calls.log\" | head -1)\n\
             if [ -z \"$saida\" ]; then echo 'fake sem diretório de saída' >&2; exit 9; fi\n\
             cat '{}' > \"$saida/zap-report.json\"\n\
             exit 0\n",
            report_path.display()
        ));
    }

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

    fn calls(&self) -> String {
        std::fs::read_to_string(self.root.join("bin").join("calls.log")).unwrap_or_default()
    }

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
fn zap_is_selectable_in_the_headless_run_and_records_image_and_version() {
    let sandbox = Sandbox::new("catalogo");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_ZAP);

    let output = sandbox.run(bin.parent().unwrap(), &["tool", "ZAP", "--target", TARGET]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "o fluxo do ZAP deveria concluir.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let calls = sandbox.calls();
    // A imagem fixada por digest e o comando sem shell chegam ao container.
    assert!(calls.contains("ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87"), "{calls}");
    assert!(
        calls.contains("zap.sh -Xmx1024m -cmd -autorun /zap/automation/scan.yaml"),
        "{calls}"
    );
    // O plano de automação é montado em somente leitura.
    assert!(calls.contains("/zap/automation:ro"), "{calls}");
    // As travas de segurança do executor permanecem.
    assert!(calls.contains("--cap-drop all"), "{calls}");
    assert!(
        calls.contains("--security-opt no-new-privileges"),
        "{calls}"
    );
    assert!(calls.contains("--read-only"), "{calls}");
    assert!(
        calls.contains("pasta:--map-host-loopback=169.254.1.2"),
        "{calls}"
    );
    // A tmpfs de HOME exigida pelo ZAP e o limite de memória de DAST.
    assert!(
        calls.contains("--tmpfs /home/zap:rw,noexec,nosuid,nodev,size=512m"),
        "{calls}"
    );
    assert!(calls.contains("--memory 1536m"), "{calls}");
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
fn the_only_writable_mount_is_the_smartsec_output_dir_and_it_is_cleaned_up() {
    let sandbox = Sandbox::new("montagem");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_ZAP);

    let output = sandbox.run(bin.parent().unwrap(), &["tool", "ZAP", "--target", TARGET]);
    assert!(output.status.success(), "{:?}", output.status);

    let create = sandbox
        .calls()
        .lines()
        .find(|line| line.starts_with("create "))
        .expect("o container deve ser criado")
        .to_string();

    // Só o diretório de saída recebe escrita; o plano de automação é montado em
    // somente leitura, como os templates do Nuclei.
    let volumes: Vec<&str> = create.split("--volume ").skip(1).collect();
    assert_eq!(volumes.len(), 2, "{create}");
    assert!(volumes[0].contains(":/zap/automation:ro "), "{create}");
    assert_eq!(
        volumes.iter().filter(|mount| mount.contains(":ro")).count(),
        1,
        "o plano de automação deve ser a única montagem somente leitura: {volumes:?}"
    );
    assert_eq!(
        volumes
            .iter()
            .filter(|mount| mount.contains(":rw,"))
            .count(),
        1,
        "o executor deve montar exatamente um diretório gravável: {volumes:?}"
    );
    assert!(
        create.contains(":/smartsec-out:rw,noexec,nosuid,nodev "),
        "{create}"
    );

    // Os diretórios criados por esta execução não sobram no host.
    //
    // O prefixo vem do `TMPDIR` do processo, e não de "/tmp" fixo: o CI
    // monta a tmpfs de trabalho em outro caminho justamente porque o `/tmp`
    // do runner é `ext4`, e um prefixo fixo encontra zero diretórios lá e
    // reprova um teste cujo requisito — a limpeza — foi cumprido.
    let prefix = format!("{}/smartsec-", std::env::temp_dir().display());
    let temporaries: Vec<&str> = volumes
        .iter()
        .filter_map(|mount| mount.split_whitespace().next())
        .filter(|host| host.starts_with(&prefix))
        .map(|host| host.split(':').next().unwrap_or(host))
        .collect();
    assert_eq!(temporaries.len(), 2, "{create}");
    for host in temporaries {
        assert!(
            !Path::new(host).exists(),
            "diretório temporário remanescente: {host}"
        );
    }
}

#[test]
fn zap_findings_reach_the_structured_log_with_url_method_and_reference() {
    let sandbox = Sandbox::new("achados");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_ZAP);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "ZAP",
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
    assert!(report.contains("ZAP"), "{report}");
    assert!(report.contains("10038"), "{report}");

    let scan_log = sandbox.latest_scan_log();
    assert!(!scan_log.is_empty(), "o log estruturado deve existir");
    // Imagem e versão registradas no log estruturado (RNF09).
    assert!(
        scan_log.contains("ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87"),
        "{scan_log}"
    );
    assert!(scan_log.contains("2.14.0"), "{scan_log}");
    // Evidência mínima: URL, método, referência, risco e confiança.
    assert!(
        scan_log.contains("url: http://169.254.1.2:3000"),
        "{scan_log}"
    );
    assert!(scan_log.contains("método: GET"), "{scan_log}");
    assert!(scan_log.contains("referência: zap:10038-1"), "{scan_log}");
    assert!(scan_log.contains("risco: Medium (High)"), "{scan_log}");
    assert!(scan_log.contains("confiança: alta"), "{scan_log}");
    // A coleta do artefato fica registrada no trace operacional.
    assert!(
        scan_log.contains("artefato /smartsec-out/zap-report.json coletado"),
        "{scan_log}"
    );
    // Nenhum corpo HTTP nem credencial.
    assert!(!scan_log.contains("requestBody"), "{scan_log}");
    assert!(!scan_log.contains("responseBody"), "{scan_log}");
}

#[test]
fn a_zap_run_without_the_report_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("sem-relatorio");
    let bin = sandbox.install_fake_podman();
    // O container encerra com status 0, mas não gera o artefato.
    sandbox.install_scripts("printf 'Automation plan succeeded!\\n'; exit 0");

    let output = sandbox.run(bin.parent().unwrap(), &["tool", "ZAP", "--target", TARGET]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !output.status.success(),
        "uma execução sem relatório não pode ser sucesso.\nstdout: {stdout}"
    );
    assert!(
        combined.contains("não gerou o relatório"),
        "a ausência do artefato precisa ser reportada.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // O container é removido mesmo sem artefato.
    assert!(sandbox
        .calls()
        .contains("rm --force --ignore container-123"));
}

#[test]
fn invalid_zap_output_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("invalido");
    let bin = sandbox.install_fake_podman();
    // Saída truncada: o container encerra com status 0, mas o artefato não é um
    // relatório JSON válido.
    sandbox.emit_report(INVALIDO);

    let output = sandbox.run(bin.parent().unwrap(), &["tool", "ZAP", "--target", TARGET]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !output.status.success(),
        "saída inválida não pode virar varredura limpa.\nstdout: {stdout}"
    );
    assert!(
        combined.contains("JSON do ZAP inválido")
            || combined.contains("não produziu relatório JSON"),
        "a saída inválida precisa ser reportada.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn a_zap_nonzero_exit_status_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("exit-status");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf 'erro interno do scanner' >&2; exit 7");

    let output = sandbox.run(bin.parent().unwrap(), &["tool", "ZAP", "--target", TARGET]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined.contains("status 7"),
        "o exit status do container precisa aparecer.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // O container é removido mesmo com falha.
    assert!(sandbox
        .calls()
        .contains("rm --force --ignore container-123"));
}

#[test]
fn the_catalog_of_the_other_tools_keeps_working_alongside_the_zap() {
    let sandbox = Sandbox::new("regressao");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(RELATORIO_ZAP);

    for tool in ["Nmap", "Nuclei", "Nikto", "ZAP"] {
        let output = sandbox.run(bin.parent().unwrap(), &["tool", tool, "--target", TARGET]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("ferramenta desconhecida"),
            "{tool} deveria estar no catálogo.\nstderr: {stderr}"
        );
    }
}
