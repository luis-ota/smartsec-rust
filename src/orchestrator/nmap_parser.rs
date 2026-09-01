#![allow(dead_code)]

use crate::domain::severity::Severity;
use crate::domain::vulnerability::Vulnerability;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmapPortFinding {
    pub port: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

pub fn parse_nmap_ports(xml: &str) -> Vec<NmapPortFinding> {
    let mut ports = Vec::new();
    let mut current: Option<NmapPortFinding> = None;
    let mut current_open = false;

    for line in xml.lines() {
        let trimmed = line.trim();

        if let Some(port) = extract_attr(trimmed, "portid") {
            if let Some(existing) = current.take() {
                if current_open {
                    ports.push(existing);
                }
            }
            current = Some(NmapPortFinding {
                port,
                service: None,
                product: None,
                version: None,
            });
            current_open = false;
        }

        if trimmed.contains("<state") && trimmed.contains("state=\"open\"") {
            current_open = true;
        }

        if let Some(ref mut finding) = current {
            if trimmed.contains("<service") {
                finding.service = extract_attr(trimmed, "name");
                finding.product = extract_attr(trimmed, "product");
                finding.version = extract_attr(trimmed, "version");
            }
        }

        if trimmed.contains("</port>") {
            if let Some(existing) = current.take() {
                if current_open {
                    ports.push(existing);
                }
            }
            current_open = false;
        }
    }

    if let Some(existing) = current.take() {
        if current_open {
            ports.push(existing);
        }
    }

    ports
}

pub fn parse_nmap_findings(xml: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let mut seen_ports: std::collections::HashSet<String> = std::collections::HashSet::new();

    for port in parse_nmap_ports(xml) {
        if !seen_ports.contains(&port.port) {
            seen_ports.insert(port.port.clone());
            if let Some(v) = build_vuln_for_port(
                &port.port,
                port.service.as_deref(),
                port.product.as_deref(),
                port.version.as_deref(),
                xml,
            ) {
                vulns.push(v);
            }
        }
    }

    vulns
}

fn build_vuln_for_port(
    port: &str,
    service: Option<&str>,
    product: Option<&str>,
    version: Option<&str>,
    full_xml: &str,
) -> Option<Vulnerability> {
    let banner_product = extract_banner_product(full_xml);
    let banner_version = extract_banner_version(full_xml);

    let svc = service.unwrap_or(banner_product.as_deref().unwrap_or("unknown"));
    let prod = product.map(String::from).or_else(|| banner_product.clone());
    let ver = version.map(String::from).or_else(|| banner_version.clone());

    let prod_str = prod.clone().unwrap_or_default();
    let ver_str = ver.clone().unwrap_or_default();

    let title = if !prod_str.is_empty() && !ver_str.is_empty() {
        format!("Port {} — {} {} exposto", port, prod_str, ver_str)
    } else if !prod_str.is_empty() {
        format!("Port {} — {} exposto", port, prod_str)
    } else {
        format!("Port {} ({}) aberta", port, svc)
    };

    let severity = severity_for_port(port, &prod_str, &ver_str);
    let recommendation = format!(
        "Restrinja o acesso à porta {} via firewall. Aplique hardening no serviço exposto.",
        port
    );

    let description = format!(
        "A porta {} está aberta e foi identificada pelo nmap como {} ({}{}). Detectado via scan -sV -sC.",
        port,
        svc,
        prod_str,
        if !ver_str.is_empty() { format!(" {}", ver_str) } else { String::new() }
    );

    let didactic = format!(
        "A porta {} está expondo um serviço {}{}.\n\nO nmap identificou esse serviço através de probes TCP e leitura de banner. Atacantes fazem o mesmo para mapear superfícies de ataque.\n\nRisco: portas abertas sem necessidade aumentam a superfície de ataque. Cada banner leak (versão, tecnologia) facilita a busca por CVEs específicos.\n\nMitigação:\n 1. Firewall restritivo (allowlist por IP).\n 2. Suprimir banners de versão ({}{}).\n 3. WAF ou reverse proxy em frente do serviço.\n 4. Patches regulares de segurança.\n 5. Monitorar tentativas de conexão.",
        port,
        svc,
        if !prod_str.is_empty() { format!(" ({})", prod_str) } else { String::new() },
        if !prod_str.is_empty() { format!(" do {}", prod_str) } else { String::new() },
        if !ver_str.is_empty() { format!(" versão {}", ver_str) } else { String::new() }
    );

    Some(Vulnerability {
        title: Box::leak(title.into_boxed_str()),
        severity,
        description: Box::leak(description.into_boxed_str()),
        tool: "Nmap",
        recommendation: Box::leak(recommendation.into_boxed_str()),
        didactic: Box::leak(didactic.into_boxed_str()),
    })
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn decode_entities(s: &str) -> String {
    s.replace("&#xa;", "\n")
        .replace("&#xA;", "\n")
        .replace("&#10;", "\n")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn unescape_nmap_fp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1] as char;
            if next == 'x' && i + 3 < bytes.len() {
                let hex = format!("{}{}", bytes[i + 2] as char, bytes[i + 3] as char);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    out.push(byte as char);
                    i += 4;
                    continue;
                }
            } else if next == 'r' {
                out.push('\r');
                i += 2;
                continue;
            } else if next == 'n' {
                out.push('\n');
                i += 2;
                continue;
            } else if next == 't' {
                out.push('\t');
                i += 2;
                continue;
            } else {
                out.push(next);
                i += 2;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn last_server_line(xml: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for raw in xml.lines() {
        if raw.contains("servicefp=") {
            continue;
        }
        let line = decode_entities(raw);
        let segments: Vec<&str> = line.split("Server:").skip(1).collect();
        if let Some(last_seg) = segments.last() {
            let seg = last_seg.trim_start();
            if let Some(first_token) = seg.split_whitespace().next() {
                if first_token.contains('/') {
                    found = Some(unescape_nmap_fp(first_token));
                }
            }
        }
    }
    found
}

fn extract_banner_product(xml: &str) -> Option<String> {
    let server = last_server_line(xml)?;
    let product = server.split('/').next()?.trim().to_string();
    if product.is_empty() {
        None
    } else {
        Some(product)
    }
}

fn extract_banner_version(xml: &str) -> Option<String> {
    let server = last_server_line(xml)?;
    let after_slash = server.split('/').nth(1)?;
    let ver = after_slash
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if ver.is_empty() {
        None
    } else {
        Some(ver)
    }
}

fn severity_for_port(port: &str, product: &str, version: &str) -> Severity {
    let p = product.to_lowercase();
    let v = version.to_lowercase();

    if p.contains("werkzeug")
        && (v.starts_with("0.") || v.starts_with("1.0") || v.starts_with("1.1"))
    {
        return Severity::High;
    }
    if p.contains("apache") || p.contains("nginx") || p.contains("iis") {
        return Severity::Medium;
    }
    if p.contains("mysql") || p.contains("postgres") || p.contains("mongodb") || p.contains("redis")
    {
        return Severity::Critical;
    }
    if p.contains("ssh") {
        return Severity::High;
    }
    if port == "22" {
        return Severity::High;
    }
    if port == "23" {
        return Severity::Critical;
    }
    if port == "80" || port == "443" || port == "8080" || port == "8443" {
        return Severity::Medium;
    }
    Severity::Info
}

#[cfg(test)]
mod tests {
        use super::{parse_nmap_findings, parse_nmap_ports};

        #[test]
        fn parses_multiline_nmap_xml_ports() {
                let xml = r#"
<nmaprun>
    <host>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack" />
                <service name="ssh" product="OpenSSH" version="9.6p1" />
            </port>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack" />
                <service name="http" product="nginx" version="1.24.0" />
            </port>
        </ports>
    </host>
</nmaprun>
"#;

                let ports = parse_nmap_ports(xml);
                assert_eq!(ports.len(), 2);
                assert_eq!(ports[0].port, "22");
                assert_eq!(ports[0].service.as_deref(), Some("ssh"));
                assert_eq!(ports[1].port, "80");
                assert_eq!(ports[1].product.as_deref(), Some("nginx"));

                let vulns = parse_nmap_findings(xml);
                assert_eq!(vulns.len(), 2);
        }
}
