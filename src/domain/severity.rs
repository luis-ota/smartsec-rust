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
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        match self {
            Severity::Critical => ratatui::style::Color::Magenta,
            Severity::High => ratatui::style::Color::Red,
            Severity::Medium => ratatui::style::Color::Yellow,
            Severity::Low => ratatui::style::Color::Cyan,
            Severity::Info => ratatui::style::Color::Gray,
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
