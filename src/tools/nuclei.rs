use crate::config::nuclei_config::NucleiConfig;
use anyhow::{anyhow, bail, Context};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub const NUCLEI_IMAGE: &str = "docker.io/projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97";
const CONTAINER_TEMPLATES_DIRECTORY: &str = "/templates";

pub struct NucleiTool {
    config: NucleiConfig,
}

impl NucleiTool {
    pub fn new(config: NucleiConfig) -> anyhow::Result<Self> {
        validate_config(&config)?;
        Ok(Self { config })
    }

    pub fn scan_timeout(&self) -> Duration {
        Duration::from_secs(self.config.scan_timeout_seconds)
    }

    pub fn templates_directory(&self) -> &Path {
        &self.config.templates_directory
    }

    pub fn configure_command(&self, target: &str) -> String {
        self.container_arguments(target).join(" ")
    }

    pub fn container_arguments(&self, target: &str) -> Vec<String> {
        let mut arguments = vec![
            "-u".to_owned(),
            target.trim().to_owned(),
            "-jsonl".to_owned(),
            "-silent".to_owned(),
            "-c".to_owned(),
            self.config.concurrency.to_string(),
            "-timeout".to_owned(),
            self.config.request_timeout_seconds.to_string(),
            "-disable-update-check".to_owned(),
            "-no-stdin".to_owned(),
        ];
        for template in &self.config.templates {
            arguments.push("-t".to_owned());
            arguments.push(
                Path::new(CONTAINER_TEMPLATES_DIRECTORY)
                    .join(template)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        arguments
    }

    pub fn validate_templates(&self) -> anyhow::Result<()> {
        if !self.config.templates_directory.is_dir() {
            bail!(
                "Templates do Nuclei {} não encontrados em '{}'. Instale essa versão nesse diretório antes de iniciar a varredura",
                crate::config::nuclei_config::NUCLEI_TEMPLATES_VERSION,
                self.config.templates_directory.display()
            );
        }
        for template in &self.config.templates {
            let path = self.config.templates_directory.join(template);
            if !path.exists() {
                bail!(
                    "Template ou diretório de templates do Nuclei não encontrado: '{}'",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

fn validate_config(config: &NucleiConfig) -> anyhow::Result<()> {
    if !(1..=100).contains(&config.concurrency) {
        bail!("A concorrência do Nuclei deve estar entre 1 e 100");
    }
    if config.request_timeout_seconds == 0 {
        bail!("O timeout de requisição do Nuclei deve ser maior que zero");
    }
    if config.scan_timeout_seconds == 0 {
        bail!("O tempo limite da varredura do Nuclei deve ser maior que zero");
    }
    if config.templates.is_empty() {
        bail!("Selecione ao menos um template ou diretório de templates do Nuclei");
    }
    for template in &config.templates {
        validate_template_selection(template)
            .with_context(|| format!("Seleção de template inválida: '{template}'"))?;
    }
    Ok(())
}

fn validate_template_selection(template: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(template);
    if template.trim().is_empty() || path.is_absolute() {
        return Err(anyhow!("use um caminho relativo não vazio"));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!("o caminho não pode conter '.' ou '..'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_configurable_container_arguments_without_a_host_shell() {
        let config = NucleiConfig {
            concurrency: 7,
            request_timeout_seconds: 11,
            templates: vec!["http/cves/".to_owned(), "ssl/".to_owned()],
            ..NucleiConfig::default()
        };
        let tool = NucleiTool::new(config).unwrap();

        assert_eq!(
            tool.container_arguments("https://example.test:8443/caminho?q=ação"),
            [
                "-u",
                "https://example.test:8443/caminho?q=ação",
                "-jsonl",
                "-silent",
                "-c",
                "7",
                "-timeout",
                "11",
                "-disable-update-check",
                "-no-stdin",
                "-t",
                "/templates/http/cves/",
                "-t",
                "/templates/ssl/"
            ]
        );
    }

    #[test]
    fn rejects_unsafe_or_unbounded_configuration() {
        let mut config = NucleiConfig::default();
        config.concurrency = 0;
        assert!(NucleiTool::new(config).is_err());

        let mut config = NucleiConfig::default();
        config.templates = vec!["../segredo.yaml".to_owned()];
        let error = NucleiTool::new(config).err().unwrap();
        assert!(error.to_string().contains("Seleção de template inválida"));
    }
}
