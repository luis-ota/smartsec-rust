//! Testes de integração da exportação de relatório no modo headless (REQ18).
//!
//! O binário `podman` é substituído pelo fake de `tests/fixtures/fake_podman`,
//! o mesmo recurso de `tests/nikto_integration.rs`: nenhum container real
//! executa e nenhum alvo externo é contatado. O alvo é sempre o loopback.
//!
//! O que estes testes cobrem é o contrato de *entrega* dos artefatos: o caminho
//! pedido pelo usuário é respeitado, o PDF é um PDF de verdade, e uma falha de
//! escrita aparece como erro com exit code 2 em vez de virar sucesso silencioso.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NMAP_XML: &str = include_str!("fixtures/nmap/open-ports.xml");
const TARGET: &str = "http://127.0.0.1:3000";

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
            "smartsec-relatorio-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("bin")).expect("o sandbox deve ser criado");
        let sandbox = Self { root };
        sandbox.install_fake_podman();
        sandbox
    }

    /// Coloca o Podman fake no PATH e faz o Nmap devolver o XML de portas.
    fn install_fake_podman(&self) -> PathBuf {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bin = self.root.join("bin");
        let target = bin.join("podman");
        std::os::unix::fs::symlink(manifest.join("tests/fixtures/fake_podman"), &target)
            .expect("o symlink do fake podman deve ser criado");
        // O fake executa estes scripts a partir de `dirname "$0"`.
        let saida = bin.join("nmap.xml");
        std::fs::write(&saida, NMAP_XML).expect("a saída do Nmap deve ser escrita");
        std::fs::write(bin.join("create.sh"), "printf 'container-123\\n'").unwrap();
        std::fs::write(
            bin.join("start.sh"),
            format!("cat '{}'; exit 0", saida.display()),
        )
        .unwrap();
        std::fs::write(bin.join("cleanup.sh"), "exit 0").unwrap();
        target
    }

    fn run(&self, extra: &[&str]) -> std::process::Output {
        let path = format!(
            "{}:{}",
            self.root.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new(env!("CARGO_BIN_EXE_smartsec-rust"))
            .args([
                "scan", "--target", TARGET, "--tools", "Nmap", "--llm", "ollama",
            ])
            .args(extra)
            .env("PATH", path)
            .env("XDG_CONFIG_HOME", &self.root)
            .env("HOME", &self.root)
            .current_dir(&self.root)
            .output()
            .expect("o binário do SmartSec deve ser executável")
    }

    fn log_estruturado_existe(&self) -> bool {
        std::fs::read_dir(self.root.join("smartsec").join("scans"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            })
            .unwrap_or(false)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Lê o texto de um PDF usando o próprio parser do printpdf.
fn texto_do_pdf(bytes: &[u8]) -> String {
    let documento = printpdf::PdfDocument::parse(
        bytes,
        &printpdf::PdfParseOptions::default(),
        &mut Vec::new(),
    )
    .expect("o PDF gerado não pôde ser relido");
    documento
        .extract_text()
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn headless_grava_markdown_e_pdf_no_caminho_pedido() {
    let sandbox = Sandbox::new("destino");
    let output = sandbox.run(&["--output", "relatorio-final.md", "--output-dir", "saida"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a varredura deveria concluir.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // O caminho vem de --output-dir combinado com --output, e não do padrão.
    let markdown = sandbox.root.join("saida").join("relatorio-final.md");
    let pdf = sandbox.root.join("saida").join("relatorio-final.pdf");
    assert!(markdown.is_file(), "Markdown ausente em {markdown:?}");
    assert!(pdf.is_file(), "PDF ausente em {pdf:?}");
    assert!(
        !sandbox.root.join("smartsec-report.md").exists(),
        "o relatório foi gravado no caminho padrão em vez do pedido"
    );

    let conteudo = std::fs::read_to_string(&markdown).expect("o Markdown deve ser lido");
    assert!(conteudo.starts_with("# SmartSec - Relatório"), "{conteudo}");
    // Os achados do Nmap fake precisam estar no relatório.
    assert!(conteudo.contains("## Resumo"), "{conteudo}");
    assert!(conteudo.contains("## Pontos Críticos"), "{conteudo}");

    let bytes = std::fs::read(&pdf).expect("o PDF deve ser lido");
    assert!(bytes.starts_with(b"%PDF-"), "o artefato não é um PDF");
    let texto = texto_do_pdf(&bytes);
    assert!(
        texto.contains("Relatório de Análise de Segurança"),
        "{texto}"
    );
    assert!(
        texto.contains("Pontos Críticos"),
        "o PDF não tem as seções do Markdown:\n{texto}"
    );
    assert!(
        stdout.contains("Relatório PDF") && stdout.contains("saida/relatorio-final.pdf"),
        "o caminho do PDF não foi informado ao usuário:\n{stdout}"
    );
}

#[test]
fn falha_de_escrita_retorna_erro_visivel_e_exit_2() {
    let sandbox = Sandbox::new("erro");
    // Um arquivo comum não pode virar diretório de saída. A falha é a mesma
    // para root e para usuário comum, ao contrário de `chmod`, que o root ignora.
    let obstaculo = sandbox.root.join("saida");
    std::fs::write(&obstaculo, "sou um arquivo, não um diretório").unwrap();

    let output = sandbox.run(&["--output-dir", "saida"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a falha de escrita tem que virar exit 2.\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    // A mensagem precisa dizer o caminho e a causa, senão o operador não sabe
    // o que corrigir.
    assert!(
        stderr.contains("não foi possível criar o diretório"),
        "{stderr}"
    );
    assert!(
        stderr.contains("saida"),
        "o caminho não aparece no erro: {stderr}"
    );
    assert!(
        stderr.contains("File exists") || stderr.contains("os error"),
        "a causa do sistema não aparece no erro: {stderr}"
    );
    // O sucesso silencioso é justamente o que não pode acontecer.
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("OK Relatório"),
        "o relatório foi anunciado como gravado apesar do erro"
    );
}

#[test]
fn o_log_estruturado_sobrevive_a_falha_de_gravacao_do_relatorio() {
    let sandbox = Sandbox::new("log");
    let obstaculo = sandbox.root.join("saida");
    std::fs::write(&obstaculo, "bloqueia o diretório").unwrap();

    let output = sandbox.run(&["--output-dir", "saida"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        sandbox.log_estruturado_existe(),
        "TCC_SPEC.md seção 10: o log estruturado é gravado antes da mensagem final"
    );
}

#[test]
fn sem_configuracao_o_relatorio_vai_para_o_caminho_padum() {
    let sandbox = Sandbox::new("padrao");
    let output = sandbox.run(&[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(sandbox.root.join("smartsec-report.md").is_file());
    assert!(sandbox.root.join("smartsec-report.pdf").is_file());
}

#[test]
fn o_ajuda_documenta_a_saida_do_relatorio() {
    let root =
        std::env::temp_dir().join(format!("smartsec-relatorio-ajuda-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_smartsec-rust"))
        .arg("--help")
        .env("XDG_CONFIG_HOME", &root)
        .env("HOME", &root)
        .current_dir(&root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("--output"), "{stdout}");
    assert!(stdout.contains("--output-dir"), "{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}
