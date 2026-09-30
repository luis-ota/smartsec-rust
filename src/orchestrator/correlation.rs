//! Correlação e deduplicação conservadora de achados (issue #19, REQ12).
//!
//! ## Regra de correlação
//!
//! Dois achados são o **mesmo problema** quando, no **mesmo alvo**, compartilham
//! uma identidade estruturada emitida pelo próprio scanner. As chaves são:
//!
//! | Chave | Origem da identidade | Exemplo |
//! |---|---|---|
//! | `cve:<id>` | Referência CVE citada por qualquer scanner | `CVE-2021-44228` |
//! | `osvdb:<id>` | Referência OSVDB do Nikto | `osvdb:4321` |
//! | `nuclei:<template>\|<matcher>@<endpoint>` | Template e matcher do Nuclei | `nuclei:cve-2021-44228\|jndi@http://alvo/app` |
//! | `nikto:<referência>@<url>` | ID de teste do Nikto no endpoint | `nikto:nikto:999957@http://alvo/` |
//! | `nmap:<porta>/<serviço>/<produto>` | Porta, serviço e banner do Nmap | `nmap:3000/http/nginx` |
//!
//! Todas as chaves incluem o alvo, então dois alvos diferentes nunca colidem.
//!
//! Uma chave só é emitida quando **todos** os componentes que a definem estão
//! presentes na evidência. Uma evidência sem identidade estruturada — por
//! exemplo a saída do parser `generic-text`, que carrega apenas a linha
//! textual do scanner — nunca produz chave e, portanto, **nunca é mesclada**.
//!
//! ## O que deliberadamente não é usado
//!
//! Semelhança textual entre `title`, `description` ou `didactic` **não** gera
//! correlação. Dois achados com textos parecidos em endpoints ou componentes
//! diferentes são problemas distintos e precisam permanecer separados: mesclá-los
//! produziria falso positivo e perderia achados.
//!
//! ## Regra de severidade do grupo
//!
//! A severidade do grupo é a **mais alta** entre as origens.
//!
//! Justificativa: a severidade estruturada de cada scanner é autoritativa
//! (TCC_SPEC.md §7). O agrupamento apenas agrega observações, não reclassifica
//! nenhuma delas. Tomar o máximo é a única regra que não pode **rebaixar** uma
//! classificação autoritativa; rebaixar esconderia um achado crítico apenas
//! porque outro scanner omitiu a mesma anomalia com rótulo menor. Quando as
//! origens divergem, as duas classificações ficam preservadas em
//! [`SeverityConflict`] e em [`FindingOrigin`]: o agrupamento nunca escolhe um
//! "vencedor".
//!
//! ## Nada se perde
//!
//! O merge agrega, nunca descarta. Cada origem entra em [`FindingOrigin`] com
//! ferramenta, severidade, evidência e timestamp próprios, inclusive a origem
//! que virou representante do grupo. Título, descrição, recomendação e
//! didático do representante são preservados; as evidências de todas as origens
//! são concatenadas em `evidence`.

use crate::domain::enrichment::{FindingOrigin, SeverityConflict};
use crate::domain::vulnerability::Vulnerability;
use crate::domain::Severity;
use std::collections::{BTreeMap, BTreeSet};

/// Resumo da operação de correlação, exibido na TUI, no headless e no relatório.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CorrelationReport {
    /// Total de achados recebidos dos parsers.
    pub input_count: usize,
    /// Total de achados após a correlação.
    pub output_count: usize,
    /// Grupos com mais de uma origem, isto é, mesclagens realmente ocorridas.
    pub merged_groups: usize,
    /// Grupos em que os scanners discordaram da severidade.
    pub conflicts: usize,
}

impl CorrelationReport {
    /// Linha única em pt-BR para a interface e para o relatório.
    pub fn summary_pt_br(&self) -> String {
        let mut summary = format!(
            "correlação: {} achados consolidados a partir de {} origens de scanner",
            self.output_count, self.input_count
        );
        if self.merged_groups > 0 {
            summary.push_str(&format!(
                "; {} grupo(s) com mais de uma ferramenta, todas as evidências preservadas",
                self.merged_groups
            ));
        }
        if self.conflicts > 0 {
            summary.push_str(&format!(
                "; {} divergência(s) de severidade preservada(s)",
                self.conflicts
            ));
        }
        summary
    }
}

/// Ranqueia as severidades para escolher o máximo sem depender da ordem do enum.
///
/// A ordem de declaração de [`Severity`] já é decrescente, mas expressar o
/// ranking explicitamente mantém a regra estável caso a enumeração mude.
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// Extrai `chave: valor` ou `chave=valor` da evidência de um achado.
///
/// Os parsers emitem dois formatos: `chave: valor | chave: valor` (Nuclei,
/// Nikto) e `chave=valor` separado por espaço (Nmap). Ambos são suportados
/// porque a regra de correlação depende de recuperar esses componentes.
///
/// A chave pode ter palavras (`nikto referência:`), então a comparação é feita
/// sobre o segmento inteiro, e não token a token. O valor é o restante do
/// segmento: as chaves usadas pela correlação têm valor sem espaço, exceto o
/// `url` do Nikto, que é registrado como endpoint e por isso precisa ser
/// preservado por inteiro.
fn field(evidence: &str, key: &str) -> Option<String> {
    for segment in evidence.split('|') {
        let Some(value) = strip_key(segment, key) else {
            continue;
        };
        let value = terminate_value(value);
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("n/a") {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

/// Corta o valor no início da próxima chave do segmento.
///
/// No formato do Nmap (`nmap porta=3000/tcp serviço=http produto=nginx`), o
/// valor termina onde a próxima chave começa. Sem isso, `serviço` absorveria o
/// resto do segmento e a identidade do scanner sairia incorreta. No formato do
/// Nuclei e do Nikto cada chave já está isolada por `|`, então nada é cortado.
fn terminate_value(value: &str) -> &str {
    let mut offset = 0;
    let mut primeira_palavra = true;
    for palavra in value.split_whitespace() {
        let inicio = offset + (value[offset..].len() - value[offset..].trim_start().len());
        let contem_separador = palavra.contains(':') || palavra.contains('=');
        if contem_separador && !primeira_palavra {
            return &value[..inicio];
        }
        primeira_palavra = false;
        offset = inicio + palavra.len();
    }
    value
}

/// Localiza `chave:` ou `chave=` dentro do segmento e devolve o valor.
///
/// A chave precisa começar num limite de palavra: `produto=` não pode casar
/// dentro de `xproduto=`. Isso importa porque o formato do Nmap é uma sequência
/// de `chave=valor` no mesmo segmento, enquanto Nuclei e Nikto usam
/// `chave: valor | chave: valor`.
fn strip_key<'a>(segment: &'a str, key: &str) -> Option<&'a str> {
    let bytes = segment.as_bytes();
    let mut from = 0;
    while let Some(found) = segment[from..].find(key) {
        let start = from + found;
        let boundary_ok = start == 0
            || !segment[..start]
                .chars()
                .next_back()
                .is_some_and(|previous| previous.is_alphanumeric() || previous == '-');
        let after = start + key.len();
        let separator = bytes.get(after).copied();
        if boundary_ok && matches!(separator, Some(b':') | Some(b'=')) {
            return Some(segment[(after + 1)..].trim_start());
        }
        from = start + key.len();
    }
    None
}

/// Componentes estruturados extraídos da evidência de um achado.
///
/// A extração é tolerante a campos ausentes, mas **nunca inventa** um
/// componente: o que não está na evidência simplesmente não é emitido.
#[derive(Debug, Default, PartialEq, Eq)]
struct EvidenceParts {
    template: Option<String>,
    matcher: Option<String>,
    endpoint: Option<String>,
    url: Option<String>,
    nikto_reference: Option<String>,
    port: Option<String>,
    service: Option<String>,
    product: Option<String>,
}

fn parse_evidence(evidence: &str) -> EvidenceParts {
    EvidenceParts {
        template: field(evidence, "template"),
        matcher: field(evidence, "matcher"),
        endpoint: field(evidence, "endpoint"),
        url: field(evidence, "url"),
        nikto_reference: field(evidence, "nikto referência"),
        port: field(evidence, "porta")
            .map(|port| port.split('/').next().unwrap_or(port.as_str()).to_string()),
        service: field(evidence, "serviço").or_else(|| field(evidence, "servico")),
        product: field(evidence, "produto"),
    }
}

/// Extrai os identificadores CVE citados na evidência ou no título.
///
/// A busca é textual e insensível a caixa: o Nuclei usa `cve-2021-44228` como
/// template id, enquanto boletins e descrições usam `CVE-2021-44228`.
fn extract_cve_ids(text: &str) -> Vec<String> {
    let uppercase = text.to_ascii_uppercase();
    let mut ids = Vec::new();
    let mut cursor = 0;
    while let Some(found) = uppercase[cursor..].find("CVE-") {
        let start = cursor + found;
        let candidate = &uppercase[start..];
        // Formato canônico: `CVE-AAAA-NNNN`, com exatamente quatro dígitos de
        // ano e ao menos quatro de sequência. Qualquer outra forma é descartada
        // em vez de virar uma chave de correlação errada.
        let year: Vec<char> = candidate[4..].chars().take(4).collect();
        let year_len = year.len();
        let sequence_start = 4 + year_len;
        let sequence = if year_len == 4 && candidate[sequence_start..].starts_with('-') {
            candidate[sequence_start + 1..]
                .chars()
                .take_while(char::is_ascii_digit)
                .count()
        } else {
            0
        };
        let consumed = sequence_start + 1 + sequence;
        let valid = year_len == 4 && year.iter().all(char::is_ascii_digit) && sequence >= 4;
        if valid {
            let id = candidate[..consumed].to_string();
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        // Avança sempre além de `CVE-`, evitando laço infinito em entradas curtas.
        cursor = start + 4;
    }
    ids
}

/// Extrai a referência OSVDB da taxonomia do Nikto.
///
/// O Nikto escreve `osvdb:0` quando o teste não tem referência, e esse valor
/// não identifica problema algum.
fn extract_osvdb(evidence: &str) -> Option<String> {
    let marker = "osvdb:";
    let lowercase = evidence.to_ascii_lowercase();
    let start = lowercase.find(marker)? + marker.len();
    let tail = &evidence[start..];
    let end = tail
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(tail.len());
    let digits = &tail[..end];
    if digits.is_empty() || digits == "0" {
        return None;
    }
    Some(digits.to_string())
}

/// Identificadores CVE citados em um texto, normalizados em maiúsculas.
///
/// Exposto para o [enriquecimento][crate::orchestrator::enrichment], que
/// consulta exatamente os mesmos identificadores que a correlação agrupou.
pub(crate) fn cve_ids_of(text: &str) -> Vec<String> {
    extract_cve_ids(text)
}

/// Identificadores cruzados, que agrupam achados de ferramentas diferentes.
///
/// A chave carrega o **endpoint** além do identificador. Sem ele, dois
/// template-distintos do mesmo CVE em páginas diferentes seriam fundidos em um
/// único achado, e a点是 de exposição em `/login` se perderia. A correlação por
/// CVE continua cruzando ferramentas — o ZAP e o Nuclei reportam o campo
/// `endpoint` — mas apenas quando apontam para o mesmo ponto.
fn shared_keys(finding: &Vulnerability, parts: &EvidenceParts) -> Vec<String> {
    let endpoint = endpoint_of(finding, parts);
    let mut keys = Vec::new();
    for cve in extract_cve_ids(&finding.evidence)
        .into_iter()
        .chain(extract_cve_ids(&finding.title))
    {
        keys.push(format!("cve:{cve}@{endpoint}"));
    }
    if let Some(osvdb) = extract_osvdb(&finding.evidence) {
        keys.push(format!("osvdb:{osvdb}@{endpoint}"));
    }
    keys
}

/// Endpoint canônico do achado: o que a evidência traz ou, na ausência, o alvo.
///
/// A URL já vem sanitizada pelos parsers (sem query string e sem credencial),
/// então a comparação entre ferramentas é feita sobre o mesmo valor.
fn endpoint_of(finding: &Vulnerability, parts: &EvidenceParts) -> String {
    parts
        .endpoint
        .as_deref()
        .or(parts.url.as_deref())
        .unwrap_or(finding.target.as_str())
        .to_string()
}

/// Identidade do próprio scanner: mesma ferramenta, mesmo teste, mesmo ponto.
///
/// Só é emitida quando a evidência traz todos os componentes do par. É isso que
/// impede a fusão de dois testes diferentes que casaram em endpoints distintos.
fn scanner_key(finding: &Vulnerability, parts: &EvidenceParts) -> Option<String> {
    let endpoint = endpoint_of(finding, parts);
    if let Some(template) = parts.template.as_deref() {
        let matcher = parts.matcher.as_deref().unwrap_or("n/a");
        return Some(format!("nuclei:{template}|{matcher}@{endpoint}"));
    }
    if let Some(reference) = parts.nikto_reference.as_deref() {
        return Some(format!("nikto:{reference}@{endpoint}"));
    }
    if let Some(port) = parts.port.as_deref() {
        let service = parts.service.as_deref().unwrap_or("n/a");
        let product = parts.product.as_deref().unwrap_or("n/a");
        return Some(format!("nmap:{port}/{service}/{product}"));
    }
    None
}

/// Todas as chaves de identidade de um achado, incluindo o alvo.
///
/// Lista vazia significa que o achado não tem identidade estrutural: ele nunca
/// será mesclado com nenhum outro.
fn identity_keys(finding: &Vulnerability) -> Vec<String> {
    let parts = parse_evidence(&finding.evidence);
    let mut keys = shared_keys(finding, &parts);
    if let Some(scanner) = scanner_key(finding, &parts) {
        keys.push(scanner);
    }
    keys.into_iter()
        .map(|key| format!("{}|alvo={}", key, finding.target))
        .collect()
}

/// Union-find por chaves: permite que dois achados de ferramentas diferentes se
/// encontrem por uma referência CVE compartilhada, sem que as ferramentas se
/// conheçam entre si.
struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            self.parent[index] = self.parent[self.parent[index]];
            index = self.parent[index];
        }
        index
    }

    fn union(&mut self, left: usize, right: usize) {
        let (left, right) = (self.root(left), self.root(right));
        if left != right {
            // A raiz menor vence para manter a ordem determinística.
            let (keep, drop) = if left < right {
                (left, right)
            } else {
                (right, left)
            };
            self.parent[drop] = keep;
        }
    }
}

/// Agrupa achados por identidade estruturada e devolve um representante por grupo.
///
/// A ordem dos achados de entrada é preservada por grupo, de modo que o
/// relatório continue estável entre execuções.
pub fn correlate(findings: Vec<Vulnerability>) -> (Vec<Vulnerability>, CorrelationReport) {
    let input_count = findings.len();
    let mut union = UnionFind::new(input_count);
    let mut key_owner: BTreeMap<String, usize> = BTreeMap::new();

    for (index, finding) in findings.iter().enumerate() {
        for key in identity_keys(finding) {
            match key_owner.get(&key) {
                Some(owner) => union.union(index, *owner),
                None => {
                    key_owner.insert(key, index);
                }
            }
        }
    }

    // Agrupa os índices por raiz preservando a ordem de entrada.
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..input_count {
        let root = union.root(index);
        groups.entry(root).or_default().push(index);
    }

    let mut output = Vec::with_capacity(groups.len());
    let mut merged_groups = 0;
    let mut conflicts = 0;

    for indices in groups.into_values() {
        let origins: Vec<FindingOrigin> = indices
            .iter()
            .map(|index| FindingOrigin::from_finding(&findings[*index]))
            .collect();
        if origins.len() > 1 {
            merged_groups += 1;
        }

        // Regra de severidade do grupo: a mais alta entre as origens.
        let group_severity = indices
            .iter()
            .map(|index| findings[*index].severity)
            .max_by_key(|severity| severity_rank(*severity))
            .unwrap_or(Severity::Info);

        // Representante: o achado de maior severidade do grupo; em caso de
        // empate, o primeiro da ordem de entrada. Assim título, descrição,
        // recomendação e didático vêm de um achado real, nunca são sintetizados.
        let representative_index = *indices
            .iter()
            .max_by_key(|index| {
                (
                    severity_rank(findings[**index].severity),
                    std::cmp::Reverse(*index),
                )
            })
            .expect("todo grupo tem ao menos um índice");

        let detail = severity_detail(&origins);
        let conflict = detail.map(|detail| SeverityConflict {
            detail,
            nvd_severity: None,
        });
        if conflict.is_some() {
            conflicts += 1;
        }

        let mut representative = findings[representative_index].clone();
        representative.severity = group_severity;
        representative.tool = origins
            .iter()
            .map(|origin| origin.tool.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        // Todas as evidências ficam acessíveis, separadas por ` || ` para não
        // confundir com o separador ` | ` usado dentro de uma evidência.
        representative.evidence = origins
            .iter()
            .map(|origin| origin.evidence.clone())
            .collect::<Vec<_>>()
            .join(" || ");
        representative.detected_at = origins
            .iter()
            .map(|origin| origin.detected_at.clone())
            .min()
            .unwrap_or_default();
        representative.origins = origins;
        representative.severity_conflict = conflict;

        output.push(representative);
    }

    let output_count = output.len();
    (
        output,
        CorrelationReport {
            input_count,
            output_count,
            merged_groups,
            conflicts,
        },
    )
}

/// Descreve em pt-BR a divergência de severidade entre as origens, se houver.
fn severity_detail(origins: &[FindingOrigin]) -> Option<String> {
    let severities: BTreeSet<&str> = origins
        .iter()
        .map(|origin| origin.severity.label_pt_br())
        .collect();
    if severities.len() < 2 {
        return None;
    }
    let detail = origins
        .iter()
        .map(|origin| format!("{}: {}", origin.tool, origin.severity.label_pt_br()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "Divergência de severidade entre scanners: {detail}. As classificações originais foram preservadas; o agrupamento exibe a mais alta."
    ))
}

/// Registra a divergência entre a severidade do scanner e a da NVD.
///
/// A severidade do scanner **não** é alterada: as duas classificações ficam
/// visíveis lado a lado (TCC_SPEC.md §7).
pub fn annotate_nvd_divergence(finding: &mut Vulnerability) {
    let Some(enrichment) = finding.enrichment.clone() else {
        return;
    };
    let Some(nvd_severity) = enrichment.cvss_severity else {
        return;
    };
    if nvd_severity == finding.severity {
        return;
    }
    let scanner_labels = if finding.origins.is_empty() {
        format!("scanner: {}", finding.severity.label_pt_br())
    } else {
        finding
            .origins
            .iter()
            .map(|origin| format!("{}: {}", origin.tool, origin.severity.label_pt_br()))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let nvd_label = nvd_severity.label_pt_br();
    let score = enrichment
        .cvss_base_score
        .map(|score| format!("{score:.1}"))
        .unwrap_or_else(|| "não pontuado".to_string());
    finding.severity_conflict = Some(SeverityConflict {
        detail: format!(
            "Divergência de severidade entre o scanner e a NVD: {scanner_labels} | NVD (CVSS {score}): {nvd_label}. As duas classificações foram preservadas; a severidade do scanner permanece autoritativa."
        ),
        nvd_severity: Some(nvd_severity),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;

    const TARGET: &str = "http://alvo.local";

    fn finding(tool: &str, severity: Severity, title: &str, evidence: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity,
            description: format!("Descrição de {title}"),
            tool: tool.to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: TARGET.to_string(),
            evidence: evidence.to_string(),
            detected_at: "2026-09-30T10:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
        }
    }

    fn nuclei(severity: Severity, matcher: &str, endpoint: &str) -> Vulnerability {
        finding(
            "Nuclei",
            severity,
            "Possível vulnerabilidade detectada — CVE-2021-44228",
            &format!("template: cve-2021-44228 | matcher: {matcher} | endpoint: {endpoint} | host: alvo.local | url: {endpoint} | tags: cve,rce"),
        )
    }

    fn nikto(id: &str, url: &str, osvdb: Option<&str>) -> Vulnerability {
        let reference = match osvdb {
            Some(osvdb) => format!("nikto:{id} osvdb:{osvdb}"),
            None => format!("nikto:{id}"),
        };
        finding(
            "Nikto",
            Severity::Low,
            &format!("Achado Nikto {reference}"),
            &format!("nikto referência: {reference} | método: GET | url: {url} | host: alvo.local | banner: nginx | msg: The anti-clickjacking header is not present."),
        )
    }

    #[test]
    fn extrai_campos_dos_dois_formatos_de_evidencia() {
        let nucleos =
            parse_evidence("template: cve-2021-44228 | matcher: jndi | endpoint: http://alvo/app");
        assert_eq!(nucleos.template.as_deref(), Some("cve-2021-44228"));
        assert_eq!(nucleos.matcher.as_deref(), Some("jndi"));
        assert_eq!(nucleos.endpoint.as_deref(), Some("http://alvo/app"));

        let nmap = parse_evidence("nmap porta=3000/tcp serviço=http produto=nginx versão=1.2");
        assert_eq!(nmap.port.as_deref(), Some("3000"));
        assert_eq!(nmap.service.as_deref(), Some("http"));
        assert_eq!(nmap.product.as_deref(), Some("nginx"));

        let nikto = parse_evidence("nikto referência: nikto:999957 | método: GET | url: http://alvo/ | msg: valor com espaços");
        assert_eq!(nikto.nikto_reference.as_deref(), Some("nikto:999957"));
        assert_eq!(nikto.url.as_deref(), Some("http://alvo/"));
    }

    /// (1) Correlação real entre duas ferramentas que citam o mesmo CVE.
    #[test]
    fn correlaciona_achados_de_ferramentas_diferentes_que_compartilham_o_cve() {
        let do_nuclei = nuclei(
            Severity::Critical,
            "jndi-injection",
            "http://alvo.local/app",
        );
        let do_nikto = finding(
            "Nikto",
            Severity::Medium,
            "Log4Shell exposto",
            "nikto referência: nikto:999001 osvdb:0 | método: GET | url: http://alvo.local/app | msg: CVE-2021-44228 exposto",
        );

        let (correlated, report) = correlate(vec![do_nuclei, do_nikto]);

        assert_eq!(report.input_count, 2);
        assert_eq!(report.output_count, 1, "o mesmo CVE é o mesmo problema");
        assert_eq!(report.merged_groups, 1);
        let group = &correlated[0];
        assert_eq!(group.origins.len(), 2, "todas as origens são preservadas");
        assert!(group.tool.contains("Nuclei") && group.tool.contains("Nikto"));
        assert!(group.evidence.contains("jndi-injection"));
        assert!(group.evidence.contains("nikto:999001"));
        assert_eq!(group.severity, Severity::Critical);
    }

    /// (2) Conflito: dois scanners discordam da severidade do mesmo problema.
    #[test]
    fn conflito_de_severidade_preserva_as_duas_classificacoes_e_exibe_a_mais_alta() {
        let do_nuclei = nuclei(
            Severity::Critical,
            "jndi-injection",
            "http://alvo.local/app",
        );
        let do_zap = finding(
            "ZAP",
            Severity::Low,
            "Log4Shell",
            "template: CVE-2021-44228 | matcher: baixa | endpoint: http://alvo.local/app",
        );

        let (correlated, report) = correlate(vec![do_nuclei, do_zap]);

        assert_eq!(
            report.conflicts, 1,
            "a divergência precisa ser contabilizada"
        );
        let group = &correlated[0];
        assert_eq!(
            group.severity,
            Severity::Critical,
            "a severidade do grupo é a mais alta entre as origens"
        );
        let severities: Vec<Severity> = group.origins.iter().map(|o| o.severity).collect();
        assert!(severities.contains(&Severity::Critical));
        assert!(
            severities.contains(&Severity::Low),
            "a classificação mais baixa continua visível: {severities:?}"
        );
        let conflict = group
            .severity_conflict
            .as_ref()
            .expect("a divergência precisa ser registrada no achado");
        assert!(conflict
            .detail
            .contains("Divergência de severidade entre scanners"));
        assert!(
            conflict.detail.contains("ZAP: BAIXA"),
            "{}",
            conflict.detail
        );
    }

    /// (3) Falso duplicado: textos parecidos, identidades diferentes.
    #[test]
    fn achados_parecidos_mas_em_endpoints_distintos_nao_sao_mesclados() {
        let primeiro = nuclei(
            Severity::Critical,
            "jndi-injection",
            "http://alvo.local/login",
        );
        let segundo = nuclei(
            Severity::Critical,
            "jndi-injection",
            "http://alvo.local/cadastro",
        );

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(
            report.output_count, 2,
            "endpoints distintos são problemas distintos"
        );
        assert_eq!(report.merged_groups, 0);
        let evidencias: BTreeSet<&str> = correlated
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect();
        assert_eq!(
            evidencias.len(),
            2,
            "cada endpoint segue acessível: {evidencias:?}"
        );
    }

    #[test]
    fn descricao_textual_parecida_nao_cria_correlacao() {
        let primeiro = nikto("999957", "http://alvo.local/", None);
        let segundo = nikto("999102", "http://alvo.local/", None);

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(
            report.output_count, 2,
            "testes diferentes do Nikto no mesmo endpoint não podem virar um achado só"
        );
        assert_eq!(report.merged_groups, 0);
        assert!(correlated[0].evidence.contains("nikto:999957"));
        assert!(correlated[1].evidence.contains("nikto:999102"));
    }

    #[test]
    fn saida_generic_text_sem_identidade_nunca_e_mesclada() {
        let primeiro = finding(
            "ZAP",
            Severity::Info,
            "Servidor expõe /admin",
            "ZAP linha=Servidor expõe /admin sem autenticação",
        );
        let segundo = finding(
            "SQLMap",
            Severity::Info,
            "Servidor expõe /admin",
            "SQLMap linha=Servidor expõe /admin sem autenticação",
        );

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(report.output_count, 2);
        assert_eq!(report.merged_groups, 0);
        assert_eq!(correlated[0].tool, "ZAP");
        assert_eq!(correlated[1].tool, "SQLMap");
    }

    #[test]
    fn alvos_diferentes_nunca_sao_correlacionados() {
        let mut primeiro = nuclei(Severity::Critical, "jndi", "http://alvo.local/app");
        let mut segundo = primeiro.clone();
        segundo.target = "http://outro.local/app".to_string();
        primeiro.target = "http://alvo.local/app".to_string();

        let (correlated, _) = correlate(vec![primeiro, segundo]);

        assert_eq!(
            correlated.len(),
            2,
            "alvos diferentes são varreduras diferentes"
        );
    }

    #[test]
    fn mesmo_template_e_matcher_no_mesmo_endpoint_e_um_duplicado_real() {
        let primeiro = nuclei(Severity::High, "jndi-injection", "http://alvo.local/app");
        let segundo = nuclei(Severity::High, "jndi-injection", "http://alvo.local/app");

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(report.output_count, 1);
        assert_eq!(report.merged_groups, 1);
        assert_eq!(report.conflicts, 0);
        assert_eq!(correlated[0].origins.len(), 2);
    }

    #[test]
    fn osvdb_compartilhado_correlaciona_testes_nikto_diferentes() {
        // Mesmo OSVDB e mesmo endpoint: são o mesmo problema visto por dois
        // testes da taxonomia do Nikto.
        let primeiro = nikto("111111", "http://alvo.local/a", Some("4321"));
        let segundo = nikto("222222", "http://alvo.local/a", Some("4321"));

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(report.output_count, 1);
        assert!(correlated[0].evidence.contains("nikto:111111"));
        assert!(correlated[0].evidence.contains("nikto:222222"));
    }

    /// O mesmo OSVDB em endpoints diferentes são pontos de exposição distintos.
    #[test]
    fn osvdb_compartilhado_em_endpoints_distintos_permanece_separado() {
        let primeiro = nikto("111111", "http://alvo.local/a", Some("4321"));
        let segundo = nikto("222222", "http://alvo.local/b", Some("4321"));

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(
            report.output_count, 2,
            "o mesmo identificador em outro endpoint é outra exposição"
        );
        assert_eq!(report.merged_groups, 0);
        assert!(correlated[0].evidence.contains("/a"));
        assert!(correlated[1].evidence.contains("/b"));
    }

    #[test]
    fn osvdb_zero_nao_vira_chave_de_correlacao() {
        assert_eq!(extract_osvdb("nikto:009004 osvdb:0"), None);
        assert_eq!(extract_osvdb("nikto:009004"), None);
        assert_eq!(
            extract_osvdb("nikto:009004 osvdb:4321"),
            Some("4321".to_string())
        );
    }

    #[test]
    fn extrai_cve_de_forma_conservadora() {
        assert_eq!(
            extract_cve_ids("template: cve-2021-44228"),
            vec!["CVE-2021-44228".to_string()]
        );
        assert_eq!(
            extract_cve_ids("e também CVE-2014-0160 aqui"),
            vec!["CVE-2014-0160".to_string()]
        );
        assert!(extract_cve_ids("cve-2021-442").is_empty());
        assert!(extract_cve_ids("cve-202-44228").is_empty());
        assert!(extract_cve_ids("CVE-21-44228").is_empty());
        assert!(extract_cve_ids("sem identificador").is_empty());
        assert_eq!(
            extract_cve_ids("CVE-2021-44228 e CVE-2021-44228"),
            vec!["CVE-2021-44228".to_string()]
        );
        assert_eq!(
            extract_cve_ids("CVE-2021-44228 e CVE-2014-0160"),
            vec!["CVE-2021-44228".to_string(), "CVE-2014-0160".to_string()]
        );
    }

    #[test]
    fn nmap_correlaciona_mesma_porta_com_mesmo_banner() {
        let primeiro = finding(
            "Nmap",
            Severity::Medium,
            "Porta 3000 — SimpleHTTPServer 0.6 exposto",
            "nmap porta=3000/tcp serviço=http produto=SimpleHTTPServer versão=0.6",
        );
        let segundo = finding(
            "Nmap",
            Severity::Low,
            "Porta 3000 — SimpleHTTPServer 0.6 exposto",
            "nmap porta=3000/tcp serviço=http produto=SimpleHTTPServer versão=0.6",
        );

        let (correlated, report) = correlate(vec![primeiro, segundo]);

        assert_eq!(report.output_count, 1);
        assert_eq!(correlated[0].severity, Severity::Medium);
        assert_eq!(correlated[0].origins.len(), 2);
        assert_eq!(report.conflicts, 1);
    }

    #[test]
    fn ports_diferentes_do_nmap_permanecem_separadas() {
        let primeiro = finding(
            "Nmap",
            Severity::Medium,
            "Porta 3000",
            "nmap porta=3000/tcp serviço=http produto=nginx versão=1.2",
        );
        let segundo = finding(
            "Nmap",
            Severity::Medium,
            "Porta 8080",
            "nmap porta=8080/tcp serviço=http produto=nginx versão=1.2",
        );

        let (correlated, _) = correlate(vec![primeiro, segundo]);

        assert_eq!(correlated.len(), 2);
    }

    #[test]
    fn correlacao_vazia_nao_falha() {
        let (correlated, report) = correlate(Vec::new());

        assert!(correlated.is_empty());
        assert_eq!(report.input_count, 0);
        assert_eq!(report.output_count, 0);
    }

    #[test]
    fn texto_descritivo_do_representante_e_preservado() {
        let primeiro = nuclei(Severity::Critical, "jndi", "http://alvo.local/app");
        let segundo = nuclei(Severity::Low, "jndi", "http://alvo.local/app");
        let antes = primeiro.clone();

        let (correlated, _) = correlate(vec![primeiro, segundo]);

        assert_eq!(correlated[0].title, antes.title);
        assert_eq!(correlated[0].description, antes.description);
        assert_eq!(correlated[0].didactic, antes.didactic);
    }

    #[test]
    fn divergencia_com_a_nvd_nao_sobrescreve_a_severidade_do_scanner() {
        let mut finding = nuclei(Severity::High, "jndi", "http://alvo.local/app");
        finding.origins = vec![FindingOrigin {
            tool: "Nuclei".to_string(),
            severity: Severity::High,
            evidence: finding.evidence.clone(),
            detected_at: finding.detected_at.clone(),
        }];
        finding.enrichment = Some(crate::domain::enrichment::CveEnrichment {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()),
            queried_at: "2026-09-30T19:11:45Z".to_string(),
            from_cache: false,
        });

        annotate_nvd_divergence(&mut finding);

        assert_eq!(
            finding.severity,
            Severity::High,
            "a severidade do scanner é autoritativa"
        );
        let conflict = finding
            .severity_conflict
            .as_ref()
            .expect("a divergência precisa ficar visível");
        assert_eq!(conflict.nvd_severity, Some(Severity::Critical));
        assert!(conflict.detail.contains("NVD (CVSS 10.0): CRÍTICA"));
        assert!(conflict.detail.contains("Nuclei: ALTA"));
    }

    #[test]
    fn severidades_iguais_entre_scanner_e_nvd_nao_geram_conflito() {
        let mut finding = nuclei(Severity::Critical, "jndi", "http://alvo.local/app");
        finding.enrichment = Some(crate::domain::enrichment::CveEnrichment {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_base_score: Some(10.0),
            cvss_vector: None,
            cvss_severity: Some(Severity::Critical),
            cvss_version: Some("3.1".to_string()),
            reference: None,
            queried_at: "2026-09-30T19:11:45Z".to_string(),
            from_cache: false,
        });

        annotate_nvd_divergence(&mut finding);

        assert!(finding.severity_conflict.is_none());
    }

    #[test]
    fn sem_enriquecimento_nao_ha_divergencia_para_registrar() {
        let mut finding = nuclei(Severity::High, "jndi", "http://alvo.local/app");

        annotate_nvd_divergence(&mut finding);

        assert!(finding.severity_conflict.is_none());
    }

    #[test]
    fn resumo_em_pt_br_cita_merge_e_conflito() {
        let (_, report) = correlate(vec![
            nuclei(
                Severity::Critical,
                "jndi-injection",
                "http://alvo.local/app",
            ),
            finding(
                "ZAP",
                Severity::Low,
                "Log4Shell",
                "template: CVE-2021-44228 | matcher: baixa | endpoint: http://alvo.local/app",
            ),
        ]);

        let summary = report.summary_pt_br();

        assert!(summary.contains("correlação"), "{summary}");
        assert!(summary.contains("divergência"), "{summary}");
        assert!(summary.contains("evidências preservadas"), "{summary}");
    }
}
