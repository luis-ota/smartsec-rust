use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const NUCLEI_TEMPLATES_VERSION: &str = "v10.2.9";
pub const NUCLEI_TEMPLATES_COMMIT: &str = "8adc92372034777469dcef575af21ba56e336f9d";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NucleiConfig {
    pub concurrency: u16,
    pub request_timeout_seconds: u64,
    pub scan_timeout_seconds: u64,
    pub templates_directory: PathBuf,
    pub templates: Vec<String>,
}

impl Default for NucleiConfig {
    fn default() -> Self {
        let data_directory = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            concurrency: 25,
            request_timeout_seconds: 5,
            scan_timeout_seconds: 15 * 60,
            templates_directory: data_directory
                .join("smartsec")
                .join(format!("nuclei-templates-{NUCLEI_TEMPLATES_VERSION}")),
            templates: vec!["http/misconfiguration/".to_owned()],
        }
    }
}
