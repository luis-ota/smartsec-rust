#[derive(Clone, Debug)]
pub struct SecurityTool {
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
}

impl SecurityTool {
    pub fn all() -> Vec<Self> {
        vec![
            SecurityTool {
                name: "ZAP",
                description: "OWASP ZAP - Web app scanner",
                category: "DAST",
            },
            SecurityTool {
                name: "Nikto",
                description: "Web server scanner",
                category: "DAST",
            },
            SecurityTool {
                name: "SQLMap",
                description: "SQL injection detector",
                category: "DAST",
            },
            SecurityTool {
                name: "Nmap",
                description: "Network port scanner",
                category: "Recon",
            },
            SecurityTool {
                name: "BurpSuite",
                description: "Web vulnerability scanner",
                category: "DAST",
            },
            SecurityTool {
                name: "Trivy",
                description: "Container/IaC scanner",
                category: "SCA",
            },
            SecurityTool {
                name: "Snyk",
                description: "Dependency vulnerability scanner",
                category: "SCA",
            },
            SecurityTool {
                name: "Bandit",
                description: "Python security linter",
                category: "SAST",
            },
        ]
    }
}
