//! Teste de integração do fluxo do SQLMap com o Podman rootless.
//!
//! O binário `podman` é substituído pelo fake de `tests/fixtures/fake_podman`,
//! que reproduz o ciclo completo do executor (info, create, start, rm) sem
//! executar qualquer container real. Isso valida o caminho do SmartSec de ponta
//! a ponta — manifesto, runner, parser e log estruturado — sem rede e sem
//! privilégios.
//!
//! O SQLMap não tem modo JSON: o fake reproduz o stdout real do scanner, com o
//! bloco `sqlmap identified the following injection point(s)`, que é a origem
//! empírica do parser (ver `docs/evidence/issue-15-sqlmap.md`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CONFIRMADA: &str = include_str!("fixtures/sqlmap/injection_confirmada.txt");
const SEM_INJECTION: &str = include_str!("fixtures/sqlmap/sem_injection.txt");
const INALCANCAVEL: &str = include_str!("fixtures/sqlmap/alvo_inalcancavel.txt");
const INVALIDO: &str = include_str!("fixtures/sqlmap/invalido.txt");

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
            "smartsec-sqlmap-{label}-{}-{unique}",
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

    /// Configura o ciclo completo do fake para emitir `output` no stdout.
    ///
    /// O conteúdo é gravado em um arquivo e impresso com `cat`, evitando
    /// interpolar a saída do scanner dentro de um script `sh`.
    fn emit_report(&self, output: &str) {
        let report_path = self.root.join("bin").join("sqlmap-stdout.txt");
        std::fs::write(&report_path, output).expect("a saída deve ser escrita");
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
const TARGET: &str = "http://127.0.0.1:3000/item?id=1";

/// Digest com que o manifesto embutido fixa a imagem do SQLMap.
const IMAGEM: &str = "docker.io/parrotsec/sqlmap:7.3@sha256:31bb35cd9fdc8c00d3673d26c48a59d2d8ea3c4955c252fb5dee2f96992b4596";

#[test]
fn sqlmap_is_selectable_in_the_headless_run_and_records_image_and_version() {
    let sandbox = Sandbox::new("catalogo");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(CONFIRMADA);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "o fluxo do SQLMap deveria concluir.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // A imagem fixada e o comando sem shell chegam ao container.
    let calls = sandbox.calls();
    assert!(calls.contains(IMAGEM), "{calls}");
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
fn sqlmap_runs_non_interactively_with_the_aggressiveness_limits() {
    let sandbox = Sandbox::new("nao-interativo");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(CONFIRMADA);

    sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );

    let calls = sandbox.calls();
    // Sem `--batch` o SQLMap trava esperando o prompt; sem `--answers`
    // ele responde `Y` e sai do escopo da varredura para atacar o banco.
    assert!(calls.contains("--batch"), "{calls}");
    assert!(calls.contains("--answers"), "{calls}");
    assert!(calls.contains("exploit=N"), "{calls}");
    // As técnicas destrutivas (stacked `S` e inline `Q`) ficam de fora.
    assert!(calls.contains("--technique=BEUT"), "{calls}");
    // Carga e tempo limitados para caber no timeout do executor.
    for limit in [
        "--threads=1",
        "--timeout=10",
        "--retries=1",
        "--time-sec=3",
        "--level=2",
        "--risk=2",
    ] {
        assert!(calls.contains(limit), "{limit} ausente em {calls}");
    }
    // O alvo entra como valor de `-u`, nunca como opção do Podman.
    assert!(
        calls.contains("-u http://127.0.0.1:3000/item?id=1"),
        "{calls}"
    );
}

#[test]
fn sqlmap_findings_reach_the_structured_log_with_parameter_and_injection_type() {
    let sandbox = Sandbox::new("achados");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(CONFIRMADA);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "SQLMap",
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
    assert!(report.contains("SQLMap"), "{report}");
    // Os tipos de injeção confirmados pelo scanner chegam ao relatório.
    assert!(report.contains("boolean-based blind"), "{report}");
    assert!(report.contains("UNION"), "{report}");

    let scan_log = sandbox.latest_scan_log();
    assert!(!scan_log.is_empty(), "o log estruturado deve existir");
    // Imagem e versão registradas no log estruturado (RNF09).
    assert!(scan_log.contains(IMAGEM), "{scan_log}");
    assert!(scan_log.contains("1.10.4"), "{scan_log}");
    // Parâmetro, método e tipo de injeção preservados.
    assert!(scan_log.contains("parâmetro: id"), "{scan_log}");
    assert!(scan_log.contains("método: GET"), "{scan_log}");
    assert!(scan_log.contains("tipo: boolean-based blind"), "{scan_log}");
    // O payload de injeção é um fragmento com forma de query string e não pode
    // aparecer em finding nem no relatório.
    assert!(!report.contains("RANDOMBLOB"), "{report}");
    assert!(!report.contains("Payload"), "{report}");
    for finding in finding_fields(&scan_log) {
        assert!(!finding.contains("RANDOMBLOB"), "{finding}");
        assert!(!finding.contains("Payload"), "{finding}");
    }
    // A query string do alvo é removida pela sanitização em todo o log.
    assert!(!scan_log.contains("?id="), "{scan_log}");
    assert!(!report.contains("?id="), "{report}");
}

/// Concatena todos os campos textuais dos achados do log estruturado.
fn finding_fields(scan_log: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(scan_log) else {
        return Vec::new();
    };
    value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .map(|findings| findings.iter().map(|finding| finding.to_string()).collect())
        .unwrap_or_default()
}

#[test]
fn a_sqlmap_run_without_injection_is_a_clean_scan_and_not_a_failure() {
    let sandbox = Sandbox::new("sem-injecao");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(SEM_INJECTION);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Não encontrar injeção é resultado legítimo e não pode virar erro.
    assert!(
        output.status.success(),
        "varredura sem injeção não é erro de execução.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !combined(&output).contains("não conseguiu executar a varredura"),
        "{}",
        combined(&output)
    );
    assert!(
        !combined(&output).contains("não produziu um resultado analisável"),
        "{}",
        combined(&output)
    );
}

#[test]
fn an_unreachable_sqlmap_target_fails_with_an_actionable_message() {
    let sandbox = Sandbox::new("inalcancavel");
    let bin = sandbox.install_fake_podman();
    // O SQLMap termina com exit status 0 mesmo sem alcançar o alvo: o
    // diagnóstico vem só do stdout, e nunca pode virar "varredura limpa".
    sandbox.emit_report(INALCANCAVEL);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "alvo inalcançável não pode ser considerado sucesso.\nstdout: {stdout}"
    );
    assert!(
        combined(&output).contains("não conseguiu executar a varredura"),
        "a falha precisa ser explicada em pt-BR.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // O container é removido mesmo com falha.
    assert!(sandbox
        .calls()
        .contains("rm --force --ignore container-123"));
}

#[test]
fn a_sqlmap_nonzero_exit_status_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("exit-status");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf 'erro interno do scanner' >&2; exit 7");

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined(&output).contains("status 7"),
        "o exit status do container precisa aparecer.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(sandbox
        .calls()
        .contains("rm --force --ignore container-123"));
}

#[test]
fn invalid_sqlmap_output_is_reported_instead_of_a_clean_scan() {
    let sandbox = Sandbox::new("invalido");
    let bin = sandbox.install_fake_podman();
    // Execução interrompida no meio: o container encerra com status 0, mas o
    // stdout não contém nem o bloco de injeção nem o diagnóstico de varredura
    // limpa.
    sandbox.emit_report(INVALIDO);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "saída inválida não pode virar varredura limpa.\nstdout: {stdout}"
    );
    assert!(
        combined(&output).contains("não contém o resultado esperado"),
        "a saída inválida precisa ser reportada.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn a_sqlmap_timeout_is_reported_with_the_executor_message() {
    let sandbox = Sandbox::new("timeout");
    let bin = sandbox.install_fake_podman();
    // O executor do SmartMap sinaliza o timeout com status diferente de zero e
    // um container que não encerra; aqui reproduzimos a saída do executor.
    sandbox.install_scripts(
        "printf '[ERRO] O container container-123 excedeu o tempo limite de 15 minutos.'; exit 125",
    );

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "SQLMap", "--target", TARGET],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined(&output).contains("tempo limite"),
        "o timeout precisa aparecer.\nstdout: {stdout}"
    );
}

#[test]
fn the_other_real_tools_keep_working_alongside_the_sqlmap_integration() {
    let sandbox = Sandbox::new("regressao");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf '<nmaprun></nmaprun>'; exit 0");

    // O catálogo embutido continua aceitando as quatro ferramentas.
    for tool in ["Nmap", "Nuclei", "Nikto", "SQLMap"] {
        let output = sandbox.run(bin.parent().unwrap(), &["tool", tool, "--target", TARGET]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("ferramenta desconhecida"),
            "{tool} deveria estar no catálogo.\nstderr: {stderr}"
        );
    }
}

fn combined(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
