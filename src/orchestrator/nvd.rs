//! Cliente da API NVD v2 para enriquecimento de achados (issue #19, REQ11).
//!
//! ## Comportamento degradado como contrato
//!
//! Timeout, HTTP 4xx/5xx, HTTP 429, DNS falhando, resposta malformada e
//! ausência de rede **nunca** interrompem a varredura e nunca derrubam o
//! relatório base. Todos esses caminhos voltam como
//! [`NvdOutcome::Unavailable`] com a causa em pt-BR, e nenhum deles usa
//! `unwrap`, `expect` ou `panic`.
//!
//! ## Limite de taxa
//!
//! A NVD publica [5 requisições a cada 30 segundos sem chave de API] e
//! [50 requisições a cada 30 segundos com chave]. O cliente aplica o intervalo
//! mínimo correspondente **entre** as requisições e trata `HTTP 429`
//! respondendo com backoff exponencial limitado, sempre dentro do teto de uma
//! requisição por consulta. Com a chave opcional em `SMARTSEC_NVD_API_KEY` o
//! intervalo cai de 6 s para 0,6 s.
//!
//! A chave é lida de variável de ambiente e **nunca** é gravada em arquivo,
//! log, relatório ou tela.
//!
//! ## Cache em disco
//!
//! Cada consulta é gravada em `~/.config/smartsec/nvd-cache/{cve}.json` com o
//! TTL documentado de [`CACHE_TTL_DAYS`] (7 dias). O dado de terceiro
//! envelhece, e o relatório precisa dizer de quando ele é: `queried_at`
//! travels junto da resposta, inclusive quando ela vem do cache.
//!
//! [5 requisições a cada 30 segundos sem chave de API]: https://nvd.nist.gov/developers/vulnerabilities
//! [50 requisições a cada 30 segundos com chave]: https://nvd.nist.gov/developers/vulnerabilities

use crate::domain::enrichment::CveEnrichment;
use crate::domain::Severity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Endpoint público da API NVD v2.
pub const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Variável de ambiente com a chave de API **opcional** da NVD.
pub const NVD_API_KEY_ENV: &str = "SMARTSEC_NVD_API_KEY";

/// TTL do cache em disco, em dias.
pub const CACHE_TTL_DAYS: u64 = 7;

/// Intervalo mínimo entre requisições sem chave de API: 5 req / 30 s.
pub const MIN_INTERVAL_SEM_CHAVE: Duration = Duration::from_secs(6);

/// Intervalo mínimo entre requisições com chave de API: 50 req / 30 s.
pub const MIN_INTERVAL_COM_CHAVE: Duration = Duration::from_millis(600);

/// Tempo limite de cada requisição HTTP.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Teto de tentativas por CVE: uma tentativa e um retry após backoff.
const MAX_ATTEMPTS: u32 = 2;

/// Backoff inicial usado quando a NVD não informa `Retry-After`.
const BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Resultado de consultar um identificador na NVD.
///
/// Os quatro casos são explícitos para que a indisponibilidade seja **visível**
/// e nunca silenciosa.
#[derive(Clone, Debug, PartialEq)]
pub enum NvdOutcome {
    /// A NVD respondeu e o CVE existe.
    Enriched(Box<CveEnrichment>),
    /// A NVD respondeu e o identificador não consta na base.
    NotFound,
    /// Enriquecimento indisponível, com a causa em pt-BR.
    Unavailable(String),
}

/// Resumo do enriquecimento de uma varredura, exibido em tela e relatório.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdReport {
    /// Identificadores distintos consultados.
    pub consulted: usize,
    /// Quantos vieram da NVD.
    pub enriched: usize,
    /// Quantos vieram do cache local dentro do TTL.
    pub cached: usize,
    /// Quantos não constam na base da NVD.
    pub not_found: usize,
    /// Causas de indisponibilidade, em pt-BR, sem duplicatas.
    #[serde(default)]
    pub unavailable_reasons: Vec<String>,
}

impl NvdReport {
    /// `true` quando a indisponibilidade da NVD precisa aparecer na interface.
    pub fn is_degraded(&self) -> bool {
        !self.unavailable_reasons.is_empty()
    }

    /// Linha única em pt-BR para a TUI, o headless e o relatório.
    pub fn summary_pt_br(&self) -> String {
        if self.consulted == 0 {
            // Mesmo sem consulta, a indisponibilidade precisa aparecer: um
            // enriquecimento pulado por falha de inicialização é um evento que
            // o leitor precisa conhecer.
            let mut summary = "NVD: nenhum identificador CVE/OSVDB para enriquecer.".to_string();
            if self.is_degraded() {
                summary.push_str(&format!(
                    " Enriquecimento NVD indisponível: {} — o relatório base foi gerado normalmente.",
                    self.unavailable_reasons.join("; ")
                ));
            }
            return summary;
        }
        let mut summary = format!(
            "NVD: {enriched} enriquecidos, {cached} do cache, {not_found} sem registro em {consulted} consultados.",
            enriched = self.enriched,
            cached = self.cached,
            not_found = self.not_found,
            consulted = self.consulted,
        );
        if self.is_degraded() {
            summary.push_str(&format!(
                " Enriquecimento NVD indisponível: {} — o relatório base foi gerado normalmente.",
                self.unavailable_reasons.join("; ")
            ));
        }
        summary
    }
}

/// Cliente da NVD com cache em disco e controle de taxa.
pub struct NvdClient {
    http: reqwest::Client,
    cache_dir: PathBuf,
    api_key: Option<String>,
    min_interval: Duration,
}

/// `true` quando a variável de ambiente da chave está presente e não vazia.
///
/// A chave em si nunca é lida para fora deste módulo.
pub fn has_api_key() -> bool {
    std::env::var(NVD_API_KEY_ENV)
        .map(|key| !key.trim().is_empty())
        .unwrap_or(false)
}

/// Limite de taxa em vigor, em pt-BR, para o relatório.
///
/// A chave nunca é impressa: apenas se existe ou não. Ela é lida de variável de
/// ambiente e não aparece em log, arquivo ou relatório.
pub fn rate_limit_pt_br() -> String {
    let com_chave = has_api_key();
    let (requisicoes, intervalo) = if com_chave {
        (50, MIN_INTERVAL_COM_CHAVE)
    } else {
        (5, MIN_INTERVAL_SEM_CHAVE)
    };
    format!(
        "{requisicoes} requisições a cada 30 s (intervalo mínimo de {} ms{}), conforme o limite publicado pela NVD",
        intervalo.as_millis(),
        if com_chave {
            ", com chave de API configurada por variável de ambiente"
        } else {
            ", sem chave de API"
        }
    )
}

/// Resposta da NVD para a consulta por `cveId`. Somente o necessário é tipado;
/// o restante da resposta é ignorado de propósito, para não persistir dados de
/// terceiros que o SmartSec não usa.
///
/// Campos desconhecidos são aceitos de propósito: a NVD acrescenta campos com
/// frequência e ignorá-los é o comportamento correto.
#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    #[serde(default)]
    id: String,
    #[serde(default)]
    references: Vec<NvdReference>,
    #[serde(default)]
    metrics: NvdMetrics,
}

#[derive(Debug, Default, Deserialize)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<NvdMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdMetric {
    #[serde(default, rename = "type")]
    metric_type: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default, rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Default, Deserialize)]
struct NvdCvssData {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default, rename = "vectorString")]
    vector_string: Option<String>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Registro gravado no cache em disco.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    cve_id: String,
    cvss_base_score: Option<f64>,
    cvss_vector: Option<String>,
    cvss_severity: Option<Severity>,
    cvss_version: Option<String>,
    reference: Option<String>,
    queried_at: String,
}

impl NvdClient {
    /// Cria o cliente usando o diretório de configuração do SmartSec.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_cache_dir(cache_dir())
    }

    /// Cria o cliente com um diretório de cache explícito (usado em teste).
    pub fn with_cache_dir(cache_dir: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&cache_dir).map_err(|error| {
            anyhow::anyhow!(
                "não foi possível criar o diretório de cache da NVD em '{}': {error}",
                cache_dir.display()
            )
        })?;
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("SmartSec/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                anyhow::anyhow!("não foi possível preparar o cliente HTTP: {error}")
            })?;
        let api_key = std::env::var(NVD_API_KEY_ENV)
            .ok()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());
        let min_interval = if api_key.is_some() {
            MIN_INTERVAL_COM_CHAVE
        } else {
            MIN_INTERVAL_SEM_CHAVE
        };
        Ok(Self {
            http,
            cache_dir,
            api_key,
            min_interval,
        })
    }

    /// `true` quando há chave de API configurada por variável de ambiente.
    #[cfg(test)]
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Intervalo mínimo a respeitar antes da próxima requisição.
    pub fn min_interval(&self) -> Duration {
        self.min_interval
    }

    /// Consulta um identificador CVE, com cache e backoff.
    ///
    /// Nunca retorna `Err`: qualquer falha vira [`NvdOutcome::Unavailable`].
    pub async fn lookup(&self, cve_id: &str) -> NvdOutcome {
        let cve_id = cve_id.trim().to_ascii_uppercase();
        if cve_id.is_empty() {
            return NvdOutcome::Unavailable("identificador CVE vazio".to_string());
        }
        // O TTL do cache é o documentado em `CACHE_TTL_DAYS`. Usar o tempo limite de
        // requisição aqui faria cada execução buscar de novo na NVD e estourar o
        // limite público de taxa sem necessidade.
        if let Some(hit) = self.read_cache(&cve_id, cache_ttl()) {
            return NvdOutcome::Enriched(Box::new(hit));
        }
        self.fetch(&cve_id).await
    }

    /// Consulta a API com um teto de tentativas e backoff exponencial limitado.
    async fn fetch(&self, cve_id: &str) -> NvdOutcome {
        let mut wait = BACKOFF_BASE;
        for attempt in 1..=MAX_ATTEMPTS {
            if attempt > 1 {
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(2);
            }
            match self.request(cve_id).await {
                Ok(outcome) => return outcome,
                Err(error) if error.retryable && attempt < MAX_ATTEMPTS => continue,
                Err(error) => return NvdOutcome::Unavailable(error.message),
            }
        }
        NvdOutcome::Unavailable(
            "a NVD excedeu o número de tentativas para este identificador".to_string(),
        )
    }

    /// Uma requisição à API, sem retry.
    ///
    /// A query string é montada por `reqwest::RequestBuilder::query`, e o
    /// segredo de autenticação viaja apenas no cabeçalho `apiKey`.
    async fn request(&self, cve_id: &str) -> Result<NvdOutcome, NvdError> {
        let mut request = self
            .http
            .get(NVD_API_BASE)
            .query(&[("cveId", cve_id)])
            .header("Accept", "application/json");
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return Err(NvdError {
                    message: format!(
                        "não foi possível consultar a NVD ({}): {}",
                        cve_id,
                        sanitize_reqwest_error(&error)
                    ),
                    retryable: is_retryable(&error),
                });
            }
        };

        let status = response.status();
        if status.as_u16() == 429 {
            // O `Retry-After` da NVD pode vir como `0` quando a proteção de
            // borda (Cloudflare) é quem bloqueou; por isso o backoff do
            // cliente é a fonte primária de espera.
            return Err(NvdError {
                message: format!(
                    "a NVD recusou novas consultas para {cve_id} por limite de taxa; aguarde alguns segundos"
                ),
                retryable: true,
            });
        }
        if status.is_server_error() {
            return Err(NvdError {
                message: format!(
                    "a NVD respondeu com erro de servidor ({}) para {cve_id}",
                    status.as_u16()
                ),
                retryable: true,
            });
        }
        if !status.is_success() {
            return Err(NvdError {
                message: format!(
                    "a NVD respondeu com status {} para {cve_id}",
                    status.as_u16()
                ),
                retryable: false,
            });
        }

        // O envelope precisa ser um objeto com `vulnerabilities`. Um array ou um texto
        // no lugar do objeto indica proxy, portal cativo ou página de erro, e
        // não uma resposta da NVD. Sem esta checagem um `[]` seria lido como
        // "CVE inexistente" e a indisponibilidade passaria por resultado limpo.
        let bruto = response.text().await.map_err(|error| NvdError {
            message: format!("a NVD devolveu resposta ilegível para {cve_id}: {error}"),
            retryable: is_retryable(&error),
        })?;
        let documento: serde_json::Value =
            serde_json::from_str(&bruto).map_err(|error| NvdError {
                message: format!("a NVD devolveu resposta malformada para {cve_id}: {error}"),
                retryable: false,
            })?;
        if !documento.is_object() {
            return Err(NvdError {
                message: format!(
                    "a NVD devolveu um documento que não é o envelope esperado para {cve_id}"
                ),
                retryable: false,
            });
        }
        let payload: NvdResponse = serde_json::from_value(documento).map_err(|error| NvdError {
            message: format!("a NVD devolveu envelope inesperado para {cve_id}: {error}"),
            retryable: false,
        })?;

        let Some(cve) = payload.vulnerabilities.into_iter().next().map(|v| v.cve) else {
            return Ok(NvdOutcome::NotFound);
        };

        let enrichment = build_enrichment(&cve, false);
        self.write_cache(&enrichment);
        Ok(NvdOutcome::Enriched(Box::new(enrichment)))
    }

    /// Lê o cache em disco respeitando o TTL.
    ///
    /// A data da consulta original é preservada: o relatório precisa declarar
    /// quando o dado de terceiro foi obtido, mesmo quando vem do cache.
    fn read_cache(&self, cve_id: &str, ttl: Duration) -> Option<CveEnrichment> {
        let path = self.cache_path(cve_id);
        let content = fs::read_to_string(path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&content).ok()?;
        let queried = chrono::DateTime::parse_from_rfc3339(&entry.queried_at).ok()?;
        let age = chrono::Utc::now().signed_duration_since(queried);
        if age.num_seconds() < 0 || age > chrono::Duration::from_std(ttl).ok()? {
            return None;
        }
        Some(CveEnrichment {
            cve_id: entry.cve_id,
            cvss_base_score: entry.cvss_base_score,
            cvss_vector: entry.cvss_vector,
            cvss_severity: entry.cvss_severity,
            cvss_version: entry.cvss_version,
            reference: entry.reference,
            queried_at: entry.queried_at,
            from_cache: true,
        })
    }

    /// Grava o cache em disco. Falha de disco não derruba o enriquecimento.
    fn write_cache(&self, enrichment: &CveEnrichment) {
        let entry = CacheEntry {
            cve_id: enrichment.cve_id.clone(),
            cvss_base_score: enrichment.cvss_base_score,
            cvss_vector: enrichment.cvss_vector.clone(),
            cvss_severity: enrichment.cvss_severity,
            cvss_version: enrichment.cvss_version.clone(),
            reference: enrichment.reference.clone(),
            queried_at: enrichment.queried_at.clone(),
        };
        if let Ok(serialized) = serde_json::to_string_pretty(&entry) {
            let _ = fs::write(self.cache_path(&enrichment.cve_id), serialized);
        }
    }

    fn cache_path(&self, cve_id: &str) -> PathBuf {
        // O identificador já é normalizado em maiúsculas alfanuméricas com
        // hífen, então serve como nome de arquivo sem sanitização adicional.
        self.cache_dir.join(format!("{cve_id}.json"))
    }
}

/// Falha de uma requisição à NVD, com a política de retry já decidida.
///
/// A distinção entre transitório e definitivo acontece aqui, no ponto onde o
/// erro é observado, e não por inspeção de texto traduzido depois.
#[derive(Debug, PartialEq, Eq)]
struct NvdError {
    /// Causa em pt-BR, já sem query string e sem segredo.
    message: String,
    /// `true` para limite de taxa, 5xx e falha de conexão.
    retryable: bool,
}

/// Extrai CVE, CVSS, referência e data da consulta de um registro da NVD.
///
/// A métrica preferencial é a `Primary` do próprio NVD, na ordem 4.0 → 3.1 →
/// 3.0 → 2.0.
fn build_enrichment(cve: &NvdCve, from_cache: bool) -> CveEnrichment {
    let (version, metric) = pick_metric(&cve.metrics);
    CveEnrichment {
        cve_id: cve.id.to_ascii_uppercase(),
        cvss_base_score: metric.and_then(|metric| metric.cvss_data.base_score),
        cvss_vector: metric.and_then(|metric| metric.cvss_data.vector_string.clone()),
        cvss_severity: metric
            .and_then(|metric| severity_from_label(metric.cvss_data.base_severity.as_deref())),
        cvss_version: version.map(str::to_string),
        reference: pick_reference(&cve.references),
        queried_at: now_iso8601(),
        from_cache,
    }
}

/// Seleciona a métrica CVSS preferencial: `Primary` do NVD, da mais nova para a
/// mais antiga. Sem métrica `Primary`, usa a primeira declarada.
fn pick_metric(metrics: &NvdMetrics) -> (Option<&'static str>, Option<&NvdMetric>) {
    let candidates: [(Option<&'static str>, &Vec<NvdMetric>); 4] = [
        (Some("4.0"), &metrics.v40),
        (Some("3.1"), &metrics.v31),
        (Some("3.0"), &metrics.v30),
        (Some("2.0"), &metrics.v2),
    ];
    for (version, list) in candidates {
        if list.is_empty() {
            continue;
        }
        let primary = list
            .iter()
            .find(|metric| metric.metric_type.as_deref() == Some("Primary"))
            .or_else(|| {
                list.iter()
                    .find(|metric| metric.source.as_deref() == Some("nvd@nist.gov"))
            })
            .unwrap_or(&list[0]);
        return (version, Some(primary));
    }
    (None, None)
}

/// Escolhe a referência pública mais informativa: aviso do fornecedor ou
/// patch tem precedência sobre entrada genérica de bases de Vulnerabilidades.
fn pick_reference(references: &[NvdReference]) -> Option<String> {
    const PREFERENCIAIS: &[&str] = &["Vendor Advisory", "Patch", "Release Notes"];
    let ranked = references.iter().find_map(|reference| {
        let url = reference.url.as_deref()?;
        PREFERENCIAIS
            .iter()
            .position(|tag| reference.tags.iter().any(|value| value == tag))
            .map(|position| (position, url.to_string()))
    });
    let url = ranked.map_or_else(
        || {
            references
                .iter()
                .find_map(|reference| reference.url.clone())
        },
        |(_, url)| Some(url),
    )?;
    let sanitized = crate::utils::redaction::sanitize_url(&url);
    (!sanitized.is_empty()).then_some(sanitized)
}

/// Traduz a severidade declarada pela NVD.
///
/// Rótulos desconhecidos viram `None`: semCVSS a NVD não diz nada, e inventar
/// uma severidade seria exatamente o que a regra de não reclassificar proíbe.
fn severity_from_label(label: Option<&str>) -> Option<Severity> {
    match label.map(|label| label.to_ascii_uppercase()).as_deref() {
        Some("CRITICAL") => Some(Severity::Critical),
        Some("HIGH") => Some(Severity::High),
        Some("MEDIUM") => Some(Severity::Medium),
        Some("LOW") => Some(Severity::Low),
        _ => None,
    }
}

/// Falhas de transporte transitórias justificam uma nova tentativa; as de
/// protocolo, não.
///
/// Timeouts contam como transitórios: a NVD responde devagar com frequência e
/// uma segunda tentativa dentro do teto da consulta costuma concluir.
fn is_retryable(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
}

/// Traduz o erro do `reqwest` para pt-BR sem vazar a URL da requisição.
///
/// A URL da NVD contém a query string com o identificador consultado, e a
/// mensagem original do `reqwest` a inclui. A evidência mínima exige que a
/// query string não apareça em log nem relatório.
fn sanitize_reqwest_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "tempo limite de espera excedido".to_string();
    }
    if error.is_connect() {
        return "não foi possível estabelecer conexão com o serviço".to_string();
    }
    if error.is_decode() {
        return "a resposta não pôde ser interpretada como JSON".to_string();
    }
    if error.is_request() {
        return "a requisição falhou antes de receber resposta".to_string();
    }
    // `error.to_string()` pode conter a URL; devolve-se a categoria, não o texto.
    "falha de rede não categorizada".to_string()
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Diretório de cache da NVD sob o diretório de configuração do SmartSec.
pub fn cache_dir() -> PathBuf {
    let base = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smartsec")
        .join("nvd-cache");
    let _ = fs::create_dir_all(&base);
    base
}

/// TTL do cache em dias, usado no relatório para datar o dado de terceiro.
pub fn cache_ttl_days() -> u64 {
    CACHE_TTL_DAYS
}

/// TTL do cache como `Duration`, usado na leitura do cache em disco.
pub fn cache_ttl() -> Duration {
    Duration::from_secs(CACHE_TTL_DAYS * 24 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_cache_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("smartsec-nvd-cache-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Trecho real da resposta da NVD v2 para `CVE-2021-44228`, com os campos
    /// que o SmartSec efetivamente usa.
    const RESPOSTA_REAL: &str = r#"{
      "resultsPerPage": 1,
      "totalResults": 1,
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "metrics": {
              "cvssMetricV31": [
                {
                  "source": "nvd@nist.gov",
                  "type": "Primary",
                  "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL"
                  },
                  "exploitabilityScore": 3.9,
                  "impactScore": 6.0
                }
              ]
            },
            "references": [
              { "url": "https://logging.apache.org/log4j/2.x/security.html", "source": "security@apache.org", "tags": ["Vendor Advisory"] },
              { "url": "https://packetstormsecurity.com/files/165225/x.html", "source": "security@apache.org", "tags": ["Third Party Advisory", "VDB Entry"] }
            ]
          }
        }
      ]
    }"#;

    /// Teste de integração real contra a API pública da NVD.
    ///
    /// Não roda por padrão: o limite público da NVD é de 5 requisições a cada
    /// 30 segundos, e a suíte emite mais que isso, então o resultado passa a
    /// depender do momento em que a suíte roda. Com o limite atingido, a
    /// resposta vira `Unavailable` e o teste falha **sem que nada tenha mudado
    /// no código** — o sinal se perde e a reprodutibilidade quebrada.
    ///
    /// Para executar sob demanda:
    /// `cargo test -- --ignored consulta_real_na_nvd`
    ///
    /// A degradação por limite de taxa, que é o comportamento mais importante
    /// deste módulo, tem cobertura offline por mock HTTP.
    #[ignore = "consulta a API publica da NVD; sujeita ao limite de taxa"]
    #[tokio::test]
    async fn consulta_real_na_nvd_persiste_cve_cvss_referencia_e_data() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        let outcome = client.lookup("CVE-2021-44228").await;

        let NvdOutcome::Enriched(enrichment) = outcome else {
            panic!("a NVD está acessível nesta máquina e deve enriquecer: {outcome:?}");
        };
        assert_eq!(enrichment.cve_id, "CVE-2021-44228");
        assert_eq!(enrichment.cvss_base_score, Some(10.0));
        assert_eq!(
            enrichment.cvss_vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        );
        assert_eq!(enrichment.cvss_severity, Some(Severity::Critical));
        assert_eq!(enrichment.cvss_version.as_deref(), Some("3.1"));
        // A NVD devolve dezenas de referências e a ordem delas muda com o
        // tempo; o critério estável é que a escolhida é uma URL pública e
        // sanitizada. A preferência por aviso de fornecedor tem teste próprio,
        // com resposta fixa, logo abaixo.
        let referencia = enrichment
            .reference
            .as_deref()
            .expect("a NVD devolve referências para a Log4Shell");
        assert!(
            referencia.starts_with("https://"),
            "a referência precisa ser uma URL pública: {referencia}"
        );
        assert!(!referencia.contains('?'), "{referencia}");
        assert!(!referencia.contains('@'), "{referencia}");
        // A data da consulta é obrigatória e precisa ser ISO-8601.
        assert!(
            chrono::DateTime::parse_from_rfc3339(&enrichment.queried_at).is_ok(),
            "{}",
            enrichment.queried_at
        );
        assert!(!enrichment.from_cache);
        // O cache em disco foi gravado.
        assert!(client.cache_path("CVE-2021-44228").exists());
    }

    /// O cache é consultado **antes** de qualquer requisição de rede, e a data da
    /// consulta original é preservada: dado de terceiro envelhece e o relatório
    /// precisa declarar quando foi obtido.
    ///
    /// O teste semeia o cache em vez de chamar a rede, para ser determinístico e
    /// para não gastar uma requisição do limite público da NVD.
    #[tokio::test]
    async fn segunda_consulta_vem_do_cache_sem_ir_a_rede() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let original = now_iso8601();
        client.write_cache(&CveEnrichment {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()),
            queried_at: original.clone(),
            from_cache: false,
        });

        let NvdOutcome::Enriched(do_cache) = client.lookup("CVE-2021-44228").await else {
            panic!("a consulta tem de vir do cache semeado");
        };

        assert!(do_cache.from_cache, "a consulta não deve ir à rede");
        assert_eq!(
            do_cache.queried_at, original,
            "a data da consulta original precisa ser preservada"
        );
        assert_eq!(do_cache.cvss_base_score, Some(10.0));
        assert_eq!(do_cache.cvss_severity, Some(Severity::Critical));
        assert!(do_cache.summary_pt_br().contains("cache local"));
    }

    /// Regressão: o cache precisa valer [`CACHE_TTL_DAYS`], e não o tempo limite de
    /// requisição.
    ///
    /// Versão anterior desta issue passava `REQUEST_TIMEOUT * 4` (40 s) para
    /// `read_cache`. Na prática isso fazia cada execução voltar à NVD, estourando o
    /// limite público de taxa sem necessidade — observado na execução real. Este
    /// teste fixa o TTL real e prova a diferença entre os dois.
    #[test]
    fn o_ttl_do_cache_e_o_documentado_e_nao_o_tempo_de_requisicao() {
        assert_eq!(cache_ttl(), Duration::from_secs(7 * 24 * 60 * 60));
        assert!(
            cache_ttl() > REQUEST_TIMEOUT,
            "o cache precisa sobreviver a uma requisição: {:?}",
            cache_ttl()
        );

        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let entrada = |dias: i64| CacheEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: None,
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: None,
            queried_at: (chrono::Utc::now() - chrono::Duration::days(dias))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        let gravar = |entrada: &CacheEntry| {
            fs::write(
                client.cache_path("CVE-2021-44228"),
                serde_json::to_string(entrada).expect("serializa"),
            )
            .expect("grava cache")
        };

        gravar(&entrada(0));
        assert!(
            client.read_cache("CVE-2021-44228", cache_ttl()).is_some(),
            "um cache recém-gravado precisa valer dentro do TTL de 7 dias"
        );

        gravar(&entrada(30));
        assert!(
            client.read_cache("CVE-2021-44228", cache_ttl()).is_none(),
            "um cache com 30 dias precisa estar vencido"
        );

        // Com o TTL de requisição, até um cache de uma hora seria descartado — é
        // exatamente o defeito que a execução real expôs.
        let uma_hora_atras: CacheEntry = CacheEntry {
            queried_at: (chrono::Utc::now() - chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ..entrada(0)
        };
        gravar(&uma_hora_atras);
        assert!(
            client
                .read_cache("CVE-2021-44228", REQUEST_TIMEOUT * 4)
                .is_none(),
            "o TTL de requisição é curto demais para valer como cache"
        );
        assert!(
            client.read_cache("CVE-2021-44228", cache_ttl()).is_some(),
            "o TTL documentado de 7 dias mantém o cache de uma hora válido"
        );
    }

    #[tokio::test]
    async fn cache_permite_enriquecer_mesmo_sem_rede() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        client.write_cache(&CveEnrichment {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: None,
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: None,
            queried_at: now_iso8601(),
            from_cache: false,
        });

        // O identificador está no cache, então nenhuma requisição é feita.
        let resultado = client.lookup("CVE-2021-44228").await;

        assert!(matches!(resultado, NvdOutcome::Enriched(_)));
    }

    /// Teste de integração real contra a API pública da NVD.
    ///
    /// Não roda por padrão: o limite público da NVD é de 5 requisições a cada
    /// 30 segundos, e a suíte emite mais que isso, então o resultado passa a
    /// depender do momento em que a suíte roda. Com o limite atingido, a
    /// resposta vira `Unavailable` e o teste falha **sem que nada tenha mudado
    /// no código** — o sinal se perde e a reprodutibilidade quebrada.
    ///
    /// Para executar sob demanda:
    /// `cargo test -- --ignored consulta_real_na_nvd`
    ///
    /// A degradação por limite de taxa, que é o comportamento mais importante
    /// deste módulo, tem cobertura offline por mock HTTP.
    #[ignore = "consulta a API publica da NVD; sujeita ao limite de taxa"]
    #[tokio::test]
    async fn cve_inexistente_vem_como_nao_encontrado_e_nao_como_erro() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        // CVE-1999-00001 existe, mas não é publicada na NVD.
        let outcome = client.lookup("CVE-1999-00001").await;

        assert_eq!(
            outcome,
            NvdOutcome::NotFound,
            "identificador sem registro é um resultado, não uma falha"
        );
    }

    #[tokio::test]
    async fn cve_malformado_responde_404_e_degrada_sem_panic() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        let outcome = client.lookup("nao-e-cve").await;

        assert!(
            matches!(outcome, NvdOutcome::Unavailable(_)),
            "a resposta de erro precisa ser degrade, não panic: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn identificador_vazio_degrada_com_mensagem_acionavel() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        let outcome = client.lookup("   ").await;

        assert_eq!(
            outcome,
            NvdOutcome::Unavailable("identificador CVE vazio".to_string())
        );
    }

    #[tokio::test]
    async fn cache_com_ttl_expirado_e_ignorado() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let vencido = CacheEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: None,
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: None,
            queried_at: (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339(),
        };
        fs::write(
            client.cache_path("CVE-2021-44228"),
            serde_json::to_string(&vencido).expect("serializa"),
        )
        .expect("grava cache");

        let vencido = client.read_cache("CVE-2021-44228", Duration::from_secs(60 * 60 * 24));

        assert!(
            vencido.is_none(),
            "um cache vencido precisa ser descartado, não usado"
        );
    }

    #[tokio::test]
    async fn cache_corrompido_e_ignorado_sem_falhar() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        fs::write(client.cache_path("CVE-2021-44228"), "{ não é json").expect("grava");

        let resultado = client.read_cache("CVE-2021-44228", Duration::from_secs(60));

        assert!(resultado.is_none());
    }

    #[tokio::test]
    async fn cache_recem_gravado_e_reaproveitado() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");
        let recente = CacheEntry {
            cve_id: "CVE-2014-0160".to_string(),
            cvss_base_score: Some(5.0),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
            cvss_severity: Some(Severity::Medium),
            cvss_version: Some("3.1".to_string()),
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string()),
            queried_at: now_iso8601(),
        };
        fs::write(
            client.cache_path("CVE-2014-0160"),
            serde_json::to_string(&recente).expect("serializa"),
        )
        .expect("grava cache");

        let hit = client
            .read_cache("CVE-2014-0160", Duration::from_secs(60 * 60 * 24))
            .expect("cache dentro do TTL");

        assert!(hit.from_cache);
        assert_eq!(hit.cvss_base_score, Some(5.0));
        assert_eq!(hit.cvss_severity, Some(Severity::Medium));
    }

    #[test]
    fn sem_chave_o_intervalo_minimo_e_o_mais_permissivo_nao() {
        let client = NvdClient::with_cache_dir(temp_cache_dir()).expect("cliente");

        // Sem SMARTSEC_NVD_API_KEY no ambiente de teste, vale o limite público.
        if std::env::var(NVD_API_KEY_ENV).is_err() {
            assert!(!client.has_api_key());
            assert_eq!(client.min_interval(), MIN_INTERVAL_SEM_CHAVE);
            assert!(rate_limit_pt_br().contains("sem chave de API"));
        }
    }

    #[test]
    fn a_descricao_do_limite_de_taxa_nao_vaza_a_chave_de_api() {
        let descricao = rate_limit_pt_br();

        assert!(!descricao.contains("SMARTSEC_NVD_API_KEY"), "{descricao}");
        assert!(!descricao.contains('='), "{descricao}");
        assert!(descricao.contains("requisições a cada 30 s"), "{descricao}");
    }

    #[test]
    fn limites_publicados_sao_os_da_nvd() {
        // 5 requisições / 30 s sem chave e 50 / 30 s com chave.
        assert_eq!(MIN_INTERVAL_SEM_CHAVE, Duration::from_secs(6));
        assert_eq!(MIN_INTERVAL_COM_CHAVE, Duration::from_millis(600));
        assert_eq!(CACHE_TTL_DAYS, 7);
    }

    #[test]
    fn parseia_a_resposta_real_e_escolhe_a_metrica_primary() {
        let response: NvdResponse =
            serde_json::from_str(RESPOSTA_REAL).expect("a resposta real precisa desserializar");

        assert_eq!(response.vulnerabilities.len(), 1);
        let cve = &response.vulnerabilities[0].cve;
        assert_eq!(cve.id, "CVE-2021-44228");
        let (version, metric) = pick_metric(&cve.metrics);
        assert_eq!(version, Some("3.1"));
        let metric = metric.expect("métrica CVSS presente");
        assert_eq!(metric.metric_type.as_deref(), Some("Primary"));
        assert_eq!(metric.cvss_data.base_score, Some(10.0));
        assert_eq!(metric.cvss_data.base_severity.as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn prefer_cvss_40_quando_a_nvd_a_publica() {
        let raw = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{"cvssMetricV40":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"CVSS:4.0/AV:N/AC:L","baseSeverity":"CRITICAL"}}],"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N","baseSeverity":"CRITICAL"}}]}}}]}"#;
        let response: NvdResponse = serde_json::from_str(raw).expect("desserializa");

        let (version, _) = pick_metric(&response.vulnerabilities[0].cve.metrics);

        assert_eq!(version, Some("4.0"));
    }

    #[test]
    fn cve_sem_cvss_nao_inventa_severidade() {
        let raw = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2024-0002","metrics":{}}}]}"#;
        let response: NvdResponse = serde_json::from_str(raw).expect("desserializa");
        let cve = &response.vulnerabilities[0].cve;

        let enrichment = build_enrichment(cve, false);

        assert_eq!(enrichment.cve_id, "CVE-2024-0002");
        assert_eq!(enrichment.cvss_base_score, None);
        assert_eq!(enrichment.cvss_severity, None);
        assert_eq!(enrichment.cvss_version, None);
        assert!(enrichment.queried_at.ends_with('Z'));
    }

    #[test]
    fn resposta_malformada_vira_erro_de_desserializacao() {
        assert!(serde_json::from_str::<NvdResponse>("{ não é json").is_err());
    }

    /// Um array não é uma resposta da NVD: o documento precisa ser um objeto com
    /// `vulnerabilities`. Sem essa checagem, um `[]` seria lido como "CVE
    /// inexistente" e a indisponibilidade passaria por resultado limpo.
    #[test]
    fn um_array_nao_e_uma_resposta_valida_da_nvd() {
        let vazio: NvdResponse =
            serde_json::from_str(r#"{"vulnerabilities":[]}"#).expect("objeto vazio é válido");
        assert!(vazio.vulnerabilities.is_empty());

        for malformado in ["[]", "\"CVE-2021-44228\"", "42", "null"] {
            let documento: serde_json::Value =
                serde_json::from_str(malformado).expect("o valor parseia");
            assert!(
                !documento.is_object(),
                "{malformado} não é o envelope da NVD e precisa ser rejeitado"
            );
        }
    }

    #[test]
    fn jsonl_e_texto_plano_nao_sao_aceitos_como_resposta() {
        assert!(serde_json::from_str::<NvdResponse>("CVE-2021-44228").is_err());
    }

    #[test]
    fn severidade_desconhecida_da_nvd_vira_none() {
        assert_eq!(
            severity_from_label(Some("CRITICAL")),
            Some(Severity::Critical)
        );
        assert_eq!(severity_from_label(Some("high")), Some(Severity::High));
        assert_eq!(severity_from_label(Some("MEDIUM")), Some(Severity::Medium));
        assert_eq!(severity_from_label(Some("LOW")), Some(Severity::Low));
        assert_eq!(severity_from_label(Some("INVENTADA")), None);
        assert_eq!(severity_from_label(None), None);
    }

    #[test]
    fn resumo_marca_indisponibilidade_para_a_interface() {
        let report = NvdReport {
            consulted: 3,
            enriched: 1,
            cached: 0,
            not_found: 1,
            unavailable_reasons: vec!["a NVD respondeu com status 503".to_string()],
        };

        assert!(report.is_degraded());
        let summary = report.summary_pt_br();
        assert!(summary.contains("1 enriquecidos"), "{summary}");
        assert!(
            summary.contains("Enriquecimento NVD indisponível"),
            "{summary}"
        );
        assert!(
            summary.contains("o relatório base foi gerado normalmente"),
            "a indisponibilidade precisa dizer que o relatório saiu: {summary}"
        );
    }

    #[test]
    fn resumo_sem_identificadores_nao_fala_em_falha() {
        let report = NvdReport::default();

        assert!(!report.is_degraded());
        assert!(report.summary_pt_br().contains("nenhum identificador"));
    }

    #[tokio::test]
    async fn erro_do_reqwest_nao_vaza_a_query_string() {
        let error = reqwest::Client::new()
            .get("https://servidor.invalido.invalid/rest?cveId=CVE-2021-44228&apiKey=segredo")
            .send()
            .await
            .expect_err("host inexistente deve falhar");

        let message = sanitize_reqwest_error(&error);

        assert!(!message.contains("cveId"), "{message}");
        assert!(!message.contains("segredo"), "{message}");
        assert!(!message.contains("http"), "{message}");
        assert!(!message.is_empty());
    }
}
