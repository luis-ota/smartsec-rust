use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label_pt_br(&self) -> &'static str {
        match self {
            Severity::Critical => "CRÍTICA",
            Severity::High => "ALTA",
            Severity::Medium => "MÉDIA",
            Severity::Low => "BAIXA",
            Severity::Info => "INFORMATIVA",
        }
    }

    #[allow(dead_code)]
    pub fn from_label(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        }
    }
}
