use crate::config::Configuration;
use crate::domain::vulnerability::Vulnerability;

#[allow(dead_code)]
pub struct Orchestrator;

impl Orchestrator {
    #[allow(dead_code)]
    pub async fn execute_analysis(_config: &Configuration, _tools: &[String]) -> Vec<Vulnerability> {
        Vulnerability::mock_all()
    }

    #[allow(dead_code)]
    pub fn determine_next_step(_current: &str, results: &[Vulnerability]) -> String {
        if results.iter().any(|v| v.severity == crate::domain::Severity::Critical) {
            "alert".to_string()
        } else {
            "report".to_string()
        }
    }
}
