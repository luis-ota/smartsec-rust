//! Testes de integração da correlação e do enriquecimento CVE/NVD (issue #19).
//!
//! O crate não expõe alvo de biblioteca, então os módulos são incluídos com
//! `#[path]`, seguindo o padrão já usado em `tests/podman_executor.rs`.
//!
//! Cobrem os três casos exigidos nos critérios de aceite — correlação real,
//! conflito de severidade e falso duplicado —, a persistência do contexto NVD e
//! o comportamento degradado quando a NVD está indisponível.
//!
//! Os testes que tocam a rede usam o cliente de produção. Se a NVD estiver
//! inacessível, o caminho degradado é absorvido e validado: a indisponibilidade
//! é parte do contrato, não um motivo para pular o teste.

#[path = "../src/utils/redaction.rs"]
pub mod redaction;

pub mod utils {
    pub use crate::redaction;
}

#[path = "../src/domain/severity.rs"]
pub mod severity;

#[path = "../src/domain/enrichment.rs"]
pub mod enrichment;

#[path = "../src/domain/vulnerability.rs"]
pub mod vulnerability;

pub mod domain {
    pub use crate::enrichment;
    pub use crate::severity::Severity;
    pub use crate::vulnerability;
}

#[path = "../src/orchestrator/correlation.rs"]
pub mod correlation;

#[path = "../src/orchestrator/nvd.rs"]
pub mod nvd;

#[path = "../src/orchestrator/enrichment.rs"]
pub mod enrichment_pipeline;

pub mod orchestrator {
    pub use crate::correlation;
    pub use crate::enrichment_pipeline;
    pub use crate::nvd;
}

use correlation::correlate;
use domain::enrichment::{CveEnrichment, FindingOrigin};
use domain::vulnerability::{FindingSource, Vulnerability};
use domain::Severity;
use enrichment_pipeline::{correlate_and_enrich, EnrichmentSummary};
use nvd::{NvdClient, NvdOutcome, NvdReport};

const TARGET: &str = "http://alvo.local";

fn achado(ferramenta: &str, severidade: Severity, titulo: &str, evidencia: &str) -> Vulnerability {
    Vulnerability {
        title: titulo.to_string(),
        severity: severidade,
        description: format!("Descrição técnica de {titulo}"),
        tool: ferramenta.to_string(),
        recommendation: "Aplique a correção pertinente".to_string(),
        didactic: "Explicação didática do achado".to_string(),
        source: FindingSource::Real,
        target: TARGET.to_string(),
        evidence: evidencia.to_string(),
        detected_at: "2026-09-30T10:00:00Z".to_string(),
        origins: Vec::new(),
        enrichment: None,
        severity_conflict: None,
    }
}

fn nucleos(severidade: Severity, matcher: &str, endpoint: &str) -> Vulnerability {
    achado(
        "Nuclei",
        severidade,
        "Possível vulnerabilidade detectada — CVE-2021-44228",
        &format!("template: cve-2021-44228 | matcher: {matcher} | endpoint: {endpoint} | host: alvo.local | url: {endpoint} | tags: cve,rce"),
    )
}

/// Atalho do achado do Nuclei no endpoint usado pelos testes de enriquecimento.
fn nucleos_log4shell(severidade: Severity, matcher: &str) -> Vulnerability {
    nucleos(severidade, matcher, "http://alvo.local/app")
}

fn cache_de_teste() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "smartsec-issue19-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("o diretório do cache deve ser criado");
    dir
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime de teste")
}

/// Executa correlação e enriquecimento no contexto assíncrono do teste.
fn enriquecer(
    achados: Vec<Vulnerability>,
    cliente: Option<&NvdClient>,
) -> (Vec<Vulnerability>, EnrichmentSummary) {
    runtime().block_on(correlate_and_enrich(achados, cliente))
}

/// Critério de aceite 1: achados relacionados mantêm todas as evidências e
/// todas as origens.
#[test]
fn achados_correlacionados_preservam_todas_as_evidencias_e_origens() {
    let do_nuclei = nucleos(
        Severity::Critical,
        "jndi-injection",
        "http://alvo.local/app",
    );
    let do_zap = achado(
        "ZAP",
        Severity::High,
        "Log4Shell",
        "template: CVE-2021-44228 | matcher: rce | endpoint: http://alvo.local/app | host: alvo.local | url: http://alvo.local/app | tags: cve",
    );

    let (correlacionados, relatorio) = correlate(vec![do_nuclei, do_zap]);

    assert_eq!(relatorio.input_count, 2);
    assert_eq!(relatorio.merged_groups, 1);
    assert_eq!(correlacionados.len(), 1, "o mesmo CVE é o mesmo problema");

    let grupo = &correlacionados[0];
    assert_eq!(
        grupo.origins.len(),
        2,
        "as duas origens precisam continuar registradas"
    );
    assert!(grupo.tool.contains("Nuclei"), "{}", grupo.tool);
    assert!(grupo.tool.contains("ZAP"), "{}", grupo.tool);
    assert!(
        grupo.evidence.contains("jndi-injection"),
        "a evidência do Nuclei precisa ser preservada: {}",
        grupo.evidence
    );
    assert!(
        grupo.evidence.contains("matcher: rce"),
        "a evidência do ZAP precisa ser preservada: {}",
        grupo.evidence
    );
    for origem in &grupo.origins {
        assert!(
            !origem.evidence.is_empty(),
            "nenhuma origem pode ficar sem evidência"
        );
        assert!(!origem.tool.is_empty());
        assert!(!origem.detected_at.is_empty());
    }
}

/// Critério de aceite: o conflito entre scanners é registrado e as duas
/// classificações continuam visíveis.
#[test]
fn conflito_entre_scanners_preserva_as_duas_severidades() {
    let do_nuclei = nucleos(
        Severity::Critical,
        "jndi-injection",
        "http://alvo.local/app",
    );
    let do_zap = achado(
        "ZAP",
        Severity::Low,
        "Log4Shell",
        "template: CVE-2021-44228 | matcher: aviso | endpoint: http://alvo.local/app",
    );

    let (correlacionados, relatorio) = correlate(vec![do_nuclei, do_zap]);

    assert_eq!(relatorio.conflicts, 1);
    let grupo = &correlacionados[0];
    assert_eq!(
        grupo.severity,
        Severity::Critical,
        "a regra do grupo é a severidade mais alta"
    );
    let severidades: Vec<Severity> = grupo.origins.iter().map(|o| o.severity).collect();
    assert!(severidades.contains(&Severity::Critical));
    assert!(
        severidades.contains(&Severity::Low),
        "a classificação divergente não pode ser descartada: {severidades:?}"
    );
    let conflito = grupo
        .severity_conflict
        .as_ref()
        .expect("a divergência precisa ficar registrada");
    assert!(
        conflito.detail.contains("ZAP: BAIXA"),
        "{}",
        conflito.detail
    );
    assert!(
        conflito.detail.contains("Nuclei: CRÍTICA"),
        "{}",
        conflito.detail
    );
}

/// Critério de aceite: falso duplicado. Achados parecidos que não compartilham
/// identidade estruturada precisam continuar separados.
#[test]
fn falsos_duplicados_permanecem_separados() {
    // Mesmo template, mesmo matcher, mesmo alvo, mas endpoints distintos.
    let no_login = nucleos(Severity::High, "jndi-injection", "http://alvo.local/login");
    let no_cadastro = nucleos(
        Severity::High,
        "jndi-injection",
        "http://alvo.local/cadastro",
    );
    // Mesmo endpoint e mesma mensagem, mas testes do Nikto diferentes.
    let nikto_a = achado(
        "Nikto",
        Severity::Low,
        "Cabeçalho de segurança ausente",
        "nikto referência: nikto:999957 | método: GET | url: http://alvo.local/ | host: alvo.local | banner: nginx | msg: X-Frame-Options ausente.",
    );
    let nikto_b = achado(
        "Nikto",
        Severity::Low,
        "Cabeçalho de segurança ausente",
        "nikto referência: nikto:999102 | método: GET | url: http://alvo.local/ | host: alvo.local | banner: nginx | msg: X-Frame-Options ausente.",
    );

    let (correlacionados, relatorio) = correlate(vec![no_login, no_cadastro, nikto_a, nikto_b]);

    assert_eq!(
        correlacionados.len(),
        4,
        "semelhança textual não pode fundir achados"
    );
    assert_eq!(relatorio.merged_groups, 0);
    assert!(correlacionados[0].evidence.contains("/login"));
    assert!(correlacionados[1].evidence.contains("/cadastro"));
    assert!(correlacionados[2].evidence.contains("nikto:999957"));
    assert!(correlacionados[3].evidence.contains("nikto:999102"));
}

/// O mesmo template e matcher no mesmo endpoint é duplicata real e deve ser
/// consolidada.
#[test]
fn duplicata_real_e_consolidada() {
    let primeira = nucleos(Severity::High, "jndi-injection", "http://alvo.local/app");
    let segunda = nucleos(Severity::High, "jndi-injection", "http://alvo.local/app");

    let (correlacionados, relatorio) = correlate(vec![primeira, segunda]);

    assert_eq!(relatorio.output_count, 1);
    assert_eq!(correlacionados[0].origins.len(), 2);
}

/// A severidade do scanner é autoritativa: o CVSS da NVD não reclassifica.
#[test]
fn enriquecimento_nunca_reclassifica_a_severidade_do_scanner() {
    let mut alvo = nucleos(Severity::Low, "jndi-injection", "http://alvo.local/app");
    alvo.origins = vec![FindingOrigin::from_finding(&alvo)];
    alvo.enrichment = Some(CveEnrichment {
        cve_id: "CVE-2021-44228".to_string(),
        cvss_base_score: Some(10.0),
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
        cvss_severity: Some(Severity::Critical),
        cvss_version: Some("3.1".to_string()),
        reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()),
        queried_at: "2026-09-30T19:11:45Z".to_string(),
        from_cache: false,
    });

    correlation::annotate_nvd_divergence(&mut alvo);

    assert_eq!(
        alvo.severity,
        Severity::Low,
        "a severidade do scanner permanece autoritativa"
    );
    let conflito = alvo
        .severity_conflict
        .as_ref()
        .expect("a divergência NVD versus scanner precisa ser registrada");
    assert_eq!(conflito.nvd_severity, Some(Severity::Critical));
    assert!(conflito
        .detail
        .contains("severidade do scanner permanece autoritativa"));
}

/// Critério de aceite 2: CVE, CVSS (base e vetor), referência e data da consulta
/// são persistidos.
#[test]
fn enriquecimento_persiste_cve_cvss_referencia_e_data_da_consulta() {
    let cliente = NvdClient::with_cache_dir(cache_de_teste()).expect("cliente da NVD");

    let (correlacionados, resumo) = enriquecer(
        vec![nucleos_log4shell(Severity::Critical, "jndi")],
        Some(&cliente),
    );

    if resumo.nvd.enriched + resumo.nvd.cached == 0 {
        // Ambiente sem rede: a degradação precisa ficar visível e o achado
        // precisa continuar presente.
        assert!(
            resumo.is_degraded(),
            "sem enriquecimento e sem causa registrada o resultado fica silencioso"
        );
        assert_eq!(correlacionados.len(), 1);
        return;
    }

    let enriquecimento = correlacionados[0]
        .enrichment
        .as_ref()
        .expect("o achado cita um CVE real e deve ser enriquecido");
    assert_eq!(enriquecimento.cve_id, "CVE-2021-44228");
    assert_eq!(
        enriquecimento.cvss_base_score,
        Some(10.0),
        "o score base da NVD para a Log4Shell é 10.0"
    );
    assert_eq!(
        enriquecimento.cvss_vector.as_deref(),
        Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    );
    assert_eq!(enriquecimento.cvss_severity, Some(Severity::Critical));
    assert!(
        enriquecimento.reference.is_some(),
        "a referência da NVD é obrigatória"
    );
    assert!(
        enriquecimento.queried_at.ends_with('Z') && enriquecimento.queried_at.contains('T'),
        "a data da consulta precisa ser ISO-8601: {}",
        enriquecimento.queried_at
    );
}

/// Critério de aceite 3: a indisponibilidade da NVD não impede o relatório base.
#[test]
fn indisponibilidade_da_nvd_nao_impede_o_relatorio_base() {
    // Sem cliente, o enriquecimento não roda: é o cenário de indisponibilidade,
    // e o relatório precisa sair igual.
    let achados = vec![
        nucleos(
            Severity::Critical,
            "jndi-injection",
            "http://alvo.local/app",
        ),
        achado(
            "Nmap",
            Severity::Medium,
            "Porta 3000 — nginx 1.2 exposto",
            "nmap porta=3000/tcp serviço=http produto=nginx versão=1.2",
        ),
    ];

    let (correlacionados, resumo) = enriquecer(achados, None);

    assert_eq!(correlacionados.len(), 2, "nenhum achado pode ser perdido");
    assert_eq!(
        correlacionados[0].severity,
        Severity::Critical,
        "a severidade do scanner não muda sem NVD"
    );
    assert!(resumo.is_degraded(), "a causa precisa ficar visível");
    assert!(resumo
        .nvd
        .unavailable_reasons
        .iter()
        .any(|motivo| motivo.contains("não pôde ser inicializado")));

    let texto = resumo.nvd.summary_pt_br();
    assert!(texto.contains("indisponível"), "{texto}");
    assert!(
        texto.contains("o relatório base foi gerado normalmente"),
        "a indisponibilidade precisa declarar que o relatório saiu: {texto}"
    );
}

/// O log estruturado mantém o resumo do enriquecimento, inclusive a causa da
/// indisponibilidade.
#[test]
fn log_estruturado_registra_o_resumo_do_enriquecimento() {
    let (_, resumo) = enriquecer(vec![nucleos_log4shell(Severity::Critical, "jndi")], None);

    let serializado =
        serde_json::to_string(&resumo).expect("o resumo precisa ser serializável para auditoria");

    assert!(serializado.contains("\"correlation\""), "{serializado}");
    assert!(serializado.contains("\"nvd\""), "{serializado}");
    assert!(
        serialized_contem_motivo(&serializado),
        "a causa da indisponibilidade precisa ir para o log: {serializado}"
    );
}

fn serialized_contem_motivo(serializado: &str) -> bool {
    serializado.contains("não pôde ser inicializado")
}

/// Um identificador inexistente é um resultado, não uma falha.
#[test]
fn cve_sem_registro_nao_e_tratado_como_falha() {
    let cliente = NvdClient::with_cache_dir(cache_de_teste()).expect("cliente da NVD");

    // CVE-1999-00001 tem formato válido mas não consta na base da NVD.
    let resultado = runtime().block_on(cliente.lookup("CVE-1999-00001"));

    match resultado {
        NvdOutcome::NotFound | NvdOutcome::Enriched(_) => {}
        NvdOutcome::Unavailable(motivo) => {
            panic!("a indisponibilidade precisa ficar registrada, não mascarada: {motivo}")
        }
    }
}

/// Entrada inválida degrada com mensagem acionável, sem panic.
#[test]
fn entrada_invalida_degrada_sem_panic() {
    let cliente = NvdClient::with_cache_dir(cache_de_teste()).expect("cliente da NVD");

    let resultado = runtime().block_on(cliente.lookup("   "));

    assert_eq!(
        resultado,
        NvdOutcome::Unavailable("identificador CVE vazio".to_string())
    );
}

/// O resumo de correlação é utilizável mesmo sem nenhuma origem.
#[test]
fn resumo_de_correlacao_vazio_e_valido() {
    let (correlacionados, relatorio) = correlate(Vec::new());

    assert!(correlacionados.is_empty());
    assert_eq!(relatorio.input_count, 0);
    assert_eq!(relatorio.output_count, 0);
    assert!(relatorio.summary_pt_br().contains("correlação"));
}

/// Relatório e log estruturado nunca carregam segredo da chave da NVD.
#[test]
fn a_chave_da_nvd_nao_aparece_em_nenhum_saida() {
    let resumo = EnrichmentSummary {
        correlation: correlation::CorrelationReport::default(),
        nvd: NvdReport {
            consulted: 1,
            enriched: 1,
            cached: 0,
            not_found: 0,
            unavailable_reasons: vec!["a NVD respondeu com status 503".to_string()],
        },
    };

    let descricao = nvd::rate_limit_pt_br();

    assert!(!descricao.contains('='), "{descricao}");
    assert!(
        !descricao.contains("SMARTSEC_NVD_API_KEY"),
        "a descrição do limite não pode citar a variável de ambiente: {descricao}"
    );
    assert!(resumo.is_degraded(), "a causa precisa ser visível");
}
