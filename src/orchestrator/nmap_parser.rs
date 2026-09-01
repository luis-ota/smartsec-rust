use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingDetails, Vulnerability};
use anyhow::Context;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "@version")]
    version: String,
    #[serde(rename = "host", default)]
    hosts: Vec<NmapHost>,
}

#[derive(Debug, Deserialize)]
struct NmapHost {
    #[serde(rename = "address", default)]
    addresses: Vec<NmapAddress>,
    #[serde(default)]
    hostnames: NmapHostnames,
    #[serde(default)]
    ports: NmapPorts,
}

#[derive(Debug, Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    address: String,
}

#[derive(Debug, Default, Deserialize)]
struct NmapHostnames {
    #[serde(rename = "hostname", default)]
    names: Vec<NmapHostname>,
}

#[derive(Debug, Deserialize)]
struct NmapHostname {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct NmapPorts {
    #[serde(rename = "port", default)]
    ports: Vec<NmapPort>,
}

#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    port: u16,
    state: NmapState,
    service: Option<NmapService>,
    #[serde(rename = "script", default)]
    scripts: Vec<NmapScript>,
}

#[derive(Debug, Deserialize)]
struct NmapState {
    #[serde(rename = "@state")]
    state: String,
    #[serde(rename = "@reason")]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extra_info: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapScript {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output")]
    output: String,
}

pub fn parse_nmap_findings(xml: &str) -> anyhow::Result<Vec<Vulnerability>> {
    let scan: NmapRun = quick_xml::de::from_str(xml)
        .context("a saída XML do Nmap é inválida e não pôde ser interpretada")?;
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for host in scan.hosts {
        let host_name = host
            .hostnames
            .names
            .first()
            .map(|hostname| hostname.name.clone())
            .or_else(|| {
                host.addresses
                    .first()
                    .map(|address| address.address.clone())
            })
            .context("o XML do Nmap contém um host sem nome ou endereço")?;

        for port in host.ports.ports {
            if port.state.state != "open" {
                continue;
            }
            if !seen.insert((host_name.clone(), port.port, port.protocol.clone())) {
                continue;
            }

            findings.push(Vulnerability {
                title: "Porta aberta detectada pelo Nmap",
                severity: Severity::Info,
                description: "O Nmap identificou uma porta aberta no alvo analisado.",
                tool: "Nmap",
                recommendation: "Confirme se o serviço deve estar exposto e restrinja o acesso por firewall quando aplicável.",
                didactic: "Uma porta aberta indica que um serviço aceita conexões nesse endereço. Valide a necessidade da exposição e mantenha o serviço atualizado.",
                details: Some(build_details(&scan.version, &host_name, port)),
            });
        }
    }

    Ok(findings)
}

fn build_details(tool_version: &str, host: &str, port: NmapPort) -> FindingDetails {
    let service = port
        .service
        .as_ref()
        .and_then(|service| service.name.clone());
    let version = port.service.as_ref().and_then(service_version);
    let mut evidence = vec![format!("estado={}", port.state.state)];
    if let Some(reason) = port.state.reason {
        evidence.push(format!("motivo={reason}"));
    }
    if let Some(service) = &port.service {
        if let Some(product) = &service.product {
            evidence.push(format!("produto={product}"));
        }
        if let Some(version) = &service.version {
            evidence.push(format!("versão={version}"));
        }
        if let Some(extra_info) = &service.extra_info {
            evidence.push(format!("informação adicional={extra_info}"));
        }
    }
    evidence.extend(
        port.scripts
            .into_iter()
            .map(|script| format!("script {}={}", script.id, script.output)),
    );

    FindingDetails {
        host: host.to_owned(),
        port: port.port,
        protocol: port.protocol,
        service,
        version,
        evidence: evidence.join("; "),
        tool_version: tool_version.to_owned(),
    }
}

fn service_version(service: &NmapService) -> Option<String> {
    let parts = [
        service.product.as_deref(),
        service.version.as_deref(),
        service.extra_info.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_open_port_evidence() {
        let xml = include_str!("../../tests/fixtures/nmap/open-ports.xml");

        let findings = parse_nmap_findings(xml).unwrap();

        assert_eq!(findings.len(), 2);
        let ssh = findings
            .iter()
            .find(|finding| finding.details.as_ref().unwrap().port == 22)
            .unwrap();
        let details = ssh.details.as_ref().unwrap();
        assert_eq!(details.host, "server.example.test");
        assert_eq!(details.protocol, "tcp");
        assert_eq!(details.service.as_deref(), Some("ssh"));
        assert_eq!(
            details.version.as_deref(),
            Some("OpenSSH 9.6p1 Ubuntu Linux; protocol 2.0")
        );
        assert!(details.evidence.contains("motivo=syn-ack"));
        assert!(details.evidence.contains("script ssh-hostkey="));
        assert_eq!(details.tool_version, "7.95");
    }

    #[test]
    fn ignores_closed_ports() {
        let xml = include_str!("../../tests/fixtures/nmap/closed-ports.xml");

        let findings = parse_nmap_findings(xml).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_invalid_xml() {
        let xml = include_str!("../../tests/fixtures/nmap/invalid.xml");

        let error = parse_nmap_findings(xml).unwrap_err();

        assert!(error.to_string().contains("saída XML do Nmap é inválida"));
    }
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
