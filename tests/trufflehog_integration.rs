//! Teste de integração do fluxo do TruffleHog com o Podman rootless.
//!
//! O binário `podman` é substituído pelo fake de `tests/fixtures/fake_podman`,
//! que reproduz o ciclo completo do executor (info, create, start, rm) sem
//! executar qualquer container real. Isso valida o caminho do SmartSec de ponta
//! a ponta — manifesto, runner, mount do repositório, parser e log estruturado
//! — sem rede e sem privilégios.
//!
//! O foco do arquivo é o requisito de segurança da issue: o segredo plantado
//! no repositório de teste **não pode aparecer** em nenhum lugar produced pelo
//! SmartSec.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const JSONL_TRUFFLEHOG: &str = include_str!("fixtures/trufflehog/repositorio.jsonl");
const NENHUM_SEGREDO: &str = include_str!("fixtures/trufflehog/nenhum_segredo.jsonl");
const INVALIDO: &str = include_str!("fixtures/trufflehog/invalido.jsonl");

/// Segredo sintético plantado no repositório de teste.
///
/// É obviamente falso e nunca esteve em nenhum serviço. Existe aqui para
/// provar que o valor detectado pelo TruffleHog não vaza para o log
/// estruturado nem para o relatório.
const SEGREDO_PLANTADO: &str = "CHAVE-DE-PRIVACAO-SINTETICA-NAO-USAR-000000000000";

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
            "smartsec-trufflehog-{label}-{}-{unique}",
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
    /// interpolar JSONL dentro de um script `sh`.
    fn emit_report(&self, report: &str) {
        let report_path = self.root.join("bin").join("trufflehog.jsonl");
        std::fs::write(&report_path, report).expect("o JSONL deve ser escrito");
        self.install_scripts(&format!("cat '{}'; exit 0", report_path.display()));
    }

    /// Configura o ciclo completo do fake: create, start e cleanup.
    fn install_scripts(&self, start: &str) {
        self.write_script("create.sh", "printf 'container-123\n'");
        self.write_script("start.sh", start);
        self.write_script("cleanup.sh", "exit 0");
    }

    /// Cria um repositório local sintético, com um segredo plantado.
    ///
    /// O repositório é um diretório comum com `.git`, que é o que o subcomando
    /// `git` do TruffleHog exige (`file://` sobre um diretório sem `.git`
    /// termina com `fatal: … does not appear to be a git repository`).
    fn create_repository(&self) -> PathBuf {
        let repository = self.root.join("repositorio");
        std::fs::create_dir_all(repository.join(".git")).expect("o repositório deve ser criado");
        std::fs::write(
            repository.join("credenciais.env"),
            format!("AWS_SECRET_ACCESS_KEY={SEGREDO_PLANTADO}\n"),
        )
        .expect("o arquivo de credenciais deve ser escrito");
        repository
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

/// URI de repositório remoto autorizado: o alvo não toca a rede nos testes,
/// porque o `podman` é o fake.
const REMOTO: &str = "https://github.com/org/repo.git";

#[test]
fn trufflehog_is_selectable_in_the_headless_run_and_records_image_and_version() {
    let sandbox = Sandbox::new("catalogo");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "o fluxo do TruffleHog deveria concluir.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // A imagem fixada e o comando sem shell chegam ao container.
    let calls = sandbox.calls();
    assert!(
        calls.contains("docker.io/trufflesecurity/trufflehog@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db"),
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
fn um_repositorio_local_e_montado_somente_leitura_no_container() {
    let sandbox = Sandbox::new("mount-ro");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
        ],
    );

    let calls = sandbox.calls();
    // O repositório entra no container, e apenas para leitura.
    assert!(
        calls.contains(&format!("--volume {}:/alvo:ro", repository.display())),
        "o repositório deve ser montado em :ro.\n{calls}"
    );
    // O caminho canônico do host viaja pelo --volume, não pelo comando.
    assert!(calls.contains("file:///alvo"), "{calls}");
    // O repositório analisado nunca é montado para escrita. Os tmpfs do
    // executor usam `:rw` por desenho, então a verificação é sobre o volume do
    // repositório specifically, não sobre a linha inteira.
    let volumes: Vec<&str> = calls
        .split("--volume ")
        .skip(1)
        .map(|rest| rest.split_whitespace().next().unwrap_or_default())
        .collect();
    assert_eq!(volumes.len(), 1, "deve haver um único volume: {calls}");
    assert!(
        volumes[0].ends_with(":/alvo:ro"),
        "o volume do repositório precisa ser somente leitura: {:?}",
        volumes[0]
    );
    assert!(!calls.contains("--privileged"), "{calls}");
    // O alvo dentro do container é o ponto fixo, e o caminho do host não vaza
    // para dentro do comando do scanner.
    let create = calls
        .lines()
        .find(|line| line.contains("create --name"))
        .expect("a linha de create deve existir");
    // O comando do scanner começa depois da imagem; o caminho do host só pode
    // aparecer na parte do `--volume`.
    let image = create
        .find("docker.io/trufflesecurity/trufflehog@sha256:")
        .expect("a imagem fixada deve aparecer na linha de create");
    let command = &create[image..];
    assert!(
        command.contains("file:///alvo"),
        "o alvo do container é o ponto de montagem.\n{command}"
    );
    assert!(!command.contains("repositorio"), "{command}");
}

#[test]
fn um_repositorio_remoto_autorizado_nao_gera_mount() {
    let sandbox = Sandbox::new("remoto");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    sandbox.run(
        bin.parent().unwrap(),
        &["tool", "TruffleHog", "--target", REMOTO],
    );

    let calls = sandbox.calls();
    // Sem mount: o alvo remoto é repassado como URI ao subcomando git.
    assert!(!calls.contains("--volume"), "{calls}");
    assert!(calls.contains(REMOTO), "{calls}");
    assert!(calls.contains("git "), "{calls}");
}

#[test]
fn o_segredo_plantado_nao_aparece_no_log_estruturado_nem_no_relatorio() {
    let sandbox = Sandbox::new("mascaramento");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
            "--output",
            "relatorio.md",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");

    let report = std::fs::read_to_string(sandbox.root.join("relatorio.md"))
        .expect("o relatório Markdown deve ser gravado");
    // Detector, arquivo, linha e verificação chegam ao relatório…
    assert!(report.contains("TruffleHog"), "{report}");
    assert!(report.contains("AWS"), "{report}");
    assert!(report.contains("credenciais.env"), "{report}");
    // …e o valor do segredo não.
    assert!(!report.contains(SEGREDO_PLANTADO), "{report}");

    let scan_log = sandbox.latest_scan_log();
    assert!(!scan_log.is_empty(), "o log estruturado deve existir");
    // Imagem e versão registradas no log estruturado (RNF09).
    assert!(
        scan_log.contains("docker.io/trufflesecurity/trufflehog@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db"),
        "{scan_log}"
    );
    assert!(scan_log.contains("3.97.9"), "{scan_log}");
    // Evidência mínima preservada: detector, arquivo, linha e verificação.
    assert!(scan_log.contains("trufflehog detector: AWS"), "{scan_log}");
    assert!(
        scan_log.contains("arquivo: config/credenciais.env"),
        "{scan_log}"
    );
    assert!(scan_log.contains("linha: 14"), "{scan_log}");
    assert!(scan_log.contains("verificado: sim"), "{scan_log}");

    // O requisito de segurança: nenhum vestígio do valor detectado.
    assert!(!scan_log.contains(SEGREDO_PLANTADO), "{scan_log}");
    assert!(!scan_log.contains("BEGIN RSA PRIVATE KEY"), "{scan_log}");
    assert!(!scan_log.contains("SecretParts"), "{scan_log}");
    assert!(!stdout.contains(SEGREDO_PLANTADO), "stdout: {stdout}");
}

#[test]
fn um_repositorio_sem_segredos_conclui_sem_achados_e_sem_erro() {
    let sandbox = Sandbox::new("limpo");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    sandbox.emit_report(NENHUM_SEGREDO);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Nenhum segredo encontrado é um resultado legítimo, não uma falha.
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(!stdout.contains("não encontrou"), "stdout: {stdout}");
}

#[test]
fn um_repositorio_inexistente_falha_com_mensagem_acionavel() {
    let sandbox = Sandbox::new("inexistente");
    let bin = sandbox.install_fake_podman();
    let missing = sandbox.root.join("nao-existe");
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &missing.display().to_string(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // O caminho é rejeitado antes do container: um alvo inexistente não pode
    // virar "varredura limpa".
    assert!(
        !output.status.success(),
        "repositório inexistente não pode ser sucesso.\nstdout: {stdout}"
    );
    assert!(
        combined.contains("não encontrado"),
        "a falha precisa ser explicada em pt-BR.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // Nenhum container é criado para um alvo que não existe.
    assert!(
        !sandbox.calls().contains("create --name"),
        "{}",
        sandbox.calls()
    );
}

#[test]
fn um_caminho_relativo_e_recusado_sem_chegar_ao_container() {
    let sandbox = Sandbox::new("relativo");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &["tool", "TruffleHog", "--target", "./repositorio"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // A validação de alvo da configuração rejeita o caminho relativo antes de
    // qualquer container: o resultado é o mesmo (recusa com mensagem em pt-BR),
    // e nenhum container é criado.
    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined.contains("IP, domínio ou URL") || combined.contains("absoluto"),
        "a falha precisa ser explicada em pt-BR.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !sandbox.calls().contains("create --name"),
        "um alvo recusado não pode criar container.\n{}",
        sandbox.calls()
    );
}

#[test]
fn um_esquema_remoto_nao_suportado_e_recusado() {
    let sandbox = Sandbox::new("ssh");
    let bin = sandbox.install_fake_podman();
    sandbox.emit_report(JSONL_TRUFFLEHOG);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            "git@github.com:org/repo.git",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        combined.contains("não suportado") || combined.contains("IP, domínio ou URL"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn um_nonzero_do_container_e_reportado_em_vez_de_varredura_limpa() {
    let sandbox = Sandbox::new("exit-status");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    sandbox.install_scripts("printf 'erro interno do scanner' >&2; exit 7");

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
        ],
    );
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
fn saida_invalida_e_reportada_em_vez_de_varredura_limpa() {
    let sandbox = Sandbox::new("invalido");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    // JSONL truncado: o container encerra com status 0, mas o registro não
    // pode ser interpretado.
    sandbox.install_scripts("printf '{\"SourceMetadata\":'; exit 0");

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !output.status.success(),
        "saída inválida não pode virar varredura limpa.\nstdout: {stdout}"
    );
    assert!(
        combined.contains("inválido"),
        "a saída inválida precisa ser reportada.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        INVALIDO.contains("Filesystem"),
        "a fixture deve continuar válida"
    );
}

#[test]
fn o_valor_do_segredo_emitido_pelo_scanner_nao_sobrevive_em_nenhum_artefato() {
    // Este é o teste que fecha a issue: o JSONL emitido pelo container **carrega
    // o segredo** em `Raw`, `RawV2`, `Redacted` e `SecretParts`, exatamente
    // como o TruffleHog real emite. O stdout do container é persistido no log
    // estruturado, então o valor precisa ser removido antes disso.
    let sandbox = Sandbox::new("stdout-bruto");
    let bin = sandbox.install_fake_podman();
    let repository = sandbox.create_repository();
    let jsonl_com_segredo = format!(
        concat!(
            r#"{{"SourceMetadata":{{"Data":{{"Filesystem":{{"file":"/alvo/config/credenciais.env","line":14}}}}}},"SourceID":1,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"{SEGREDO_PLANTADO}","RawV2":"{SEGREDO_PLANTADO}","Redacted":"{SEGREDO_PLANTADO}","ExtraData":{{}},"SecretParts":{{"token":"{SEGREDO_PLANTADO}"}}}}"#,
            "\n"
        ),
        SEGREDO_PLANTADO = SEGREDO_PLANTADO
    );
    sandbox.emit_report(&jsonl_com_segredo);

    let output = sandbox.run(
        bin.parent().unwrap(),
        &[
            "tool",
            "TruffleHog",
            "--target",
            &repository.display().to_string(),
            "--output",
            "relatorio.md",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let scan_log = sandbox.latest_scan_log();
    assert!(!scan_log.is_empty(), "o log estruturado deve existir");
    let report = std::fs::read_to_string(sandbox.root.join("relatorio.md"))
        .expect("o relatório Markdown deve ser gravado");

    // O achado existe e é útil…
    assert!(
        report.contains("AWS") && report.contains("credenciais.env"),
        "{report}"
    );
    assert!(scan_log.contains("trufflehog detector: AWS"), "{scan_log}");

    // …mas o valor não aparece em nenhum dos artefatos.
    for (artefato, conteudo) in [
        ("log estruturado", scan_log.as_str()),
        ("relatório", report.as_str()),
        ("stdout", stdout.as_ref()),
        ("stderr", stderr.as_ref()),
        ("chamadas do podman", sandbox.calls().as_str()),
    ] {
        assert!(
            !conteudo.contains(SEGREDO_PLANTADO),
            "o valor do segredo vazou no {artefato}"
        );
        assert!(
            !conteudo.contains("SecretParts") && !conteudo.contains("\"Raw\""),
            "os campos de valor do TruffleHog sobreviveram no {artefato}: {conteudo}"
        );
    }
}

#[test]
fn as_ferramentas_existentes_continuam_funcionando_ao_lado_do_trufflehog() {
    let sandbox = Sandbox::new("regressao");
    let bin = sandbox.install_fake_podman();
    sandbox.install_scripts("printf '<nmaprun></nmaprun>'; exit 0");

    // O catálogo embutido continua aceitando as quatro ferramentas.
    for tool in ["Nmap", "Nuclei", "Nikto", "TruffleHog"] {
        let output = sandbox.run(
            bin.parent().unwrap(),
            &["tool", tool, "--target", "http://127.0.0.1:3000"],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("ferramenta desconhecida"),
            "{tool} deveria estar no catálogo.\nstderr: {stderr}"
        );
    }
}
