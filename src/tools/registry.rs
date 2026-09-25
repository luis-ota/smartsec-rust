use crate::tools::manifest::ToolManifest;
use crate::tools::nmap::{NMAP_IMAGE, NMAP_VERSION};
use crate::tools::nuclei::{NUCLEI_IMAGE, NUCLEI_VERSION};

/// Runners registrados: executam o manifesto dentro do executor Podman rootless.
pub const RUNNER_NMAP: &str = "nmap";
pub const RUNNER_NUCLEI: &str = "nuclei";
pub const RUNNER_GENERIC: &str = "generic";

/// Parsers registrados: convertem a saída de um runner em achados.
pub const PARSER_NMAP_XML: &str = "nmap-xml";
pub const PARSER_NUCLEI_JSONL: &str = "nuclei-jsonl";
pub const PARSER_GENERIC_TEXT: &str = "generic-text";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerKind {
    Nmap,
    Nuclei,
    Generic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserKind {
    NmapXml,
    NucleiJsonl,
    GenericText,
}

fn runner_kind(runner: &str) -> Option<RunnerKind> {
    match runner.trim() {
        RUNNER_NMAP => Some(RunnerKind::Nmap),
        RUNNER_NUCLEI => Some(RunnerKind::Nuclei),
        RUNNER_GENERIC => Some(RunnerKind::Generic),
        _ => None,
    }
}

fn parser_kind(parser: &str) -> Option<ParserKind> {
    match parser.trim() {
        PARSER_NMAP_XML => Some(ParserKind::NmapXml),
        PARSER_NUCLEI_JSONL => Some(ParserKind::NucleiJsonl),
        PARSER_GENERIC_TEXT => Some(ParserKind::GenericText),
        _ => None,
    }
}

fn registered_runners() -> String {
    [RUNNER_NMAP, RUNNER_NUCLEI, RUNNER_GENERIC].join(", ")
}

fn registered_parsers() -> String {
    [PARSER_NMAP_XML, PARSER_NUCLEI_JSONL, PARSER_GENERIC_TEXT].join(", ")
}

/// Ferramenta embutida ou registrada por configuração, já validada e ligada a
/// um runner e a um parser conhecidos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredTool {
    pub manifest: ToolManifest,
    pub runner: RunnerKind,
    pub parser: ParserKind,
}

/// Catálogo de ferramentas do SmartSec.
///
/// Contém os manifestos embutidos (Nmap e Nuclei) e as ferramentas registradas
/// pela chave `[[tools]]` do TOML. Ferramentas duplicadas, campos obrigatórios
/// ausentes e runner/parser desconhecidos produzem erros acionáveis em pt-BR.
#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    tools: Vec<RegisteredTool>,
    errors: Vec<String>,
}

impl ToolRegistry {
    /// Catálogo com as ferramentas embutidas.
    pub fn builtin() -> Self {
        let mut registry = Self::default();
        registry.push_builtin(nmap_manifest(), RunnerKind::Nmap, ParserKind::NmapXml);
        registry.push_builtin(
            nuclei_manifest(),
            RunnerKind::Nuclei,
            ParserKind::NucleiJsonl,
        );
        registry
    }

    /// Monta o catálogo com embutidas + configuradas.
    ///
    /// É infalível: entradas inválidas são registradas em `errors()` e ficam
    /// fora do catálogo. Use [`ToolRegistry::with_configured`] quando a
    /// configuração inválida precisar interromper o fluxo.
    pub fn load(configured: &[ToolManifest]) -> Self {
        let mut registry = Self::builtin();
        for (position, manifest) in configured.iter().enumerate() {
            if let Err(error) = registry.register_configured(manifest, position) {
                registry.errors.push(error);
            }
        }
        registry
    }

    /// Igual a [`ToolRegistry::load`], mas devolve erro quando a configuração
    /// contém qualquer entrada inválida.
    pub fn with_configured(configured: &[ToolManifest]) -> anyhow::Result<Self> {
        let registry = Self::load(configured);
        if registry.errors().is_empty() {
            Ok(registry)
        } else {
            anyhow::bail!(
                "configuração de ferramentas inválida:\n- {}",
                registry.errors().join("\n- ")
            )
        }
    }

    pub fn tools(&self) -> &[RegisteredTool] {
        &self.tools
    }

    pub fn find(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools
            .iter()
            .find(|tool| tool.manifest.name.eq_ignore_ascii_case(name.trim()))
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    fn push_builtin(&mut self, manifest: ToolManifest, runner: RunnerKind, parser: ParserKind) {
        debug_assert!(manifest.validate(0).is_ok(), "manifesto embutido inválido");
        self.tools.push(RegisteredTool {
            manifest,
            runner,
            parser,
        });
    }

    fn register_configured(
        &mut self,
        manifest: &ToolManifest,
        position: usize,
    ) -> Result<(), String> {
        manifest.validate(position)?;
        let label = format!("a ferramenta '{}'", manifest.name.trim());
        let runner = runner_kind(&manifest.runner).ok_or_else(|| {
            format!(
                "{label} usa o runner desconhecido '{}'; runners registrados: {}",
                manifest.runner.trim(),
                registered_runners()
            )
        })?;
        let parser = parser_kind(&manifest.parser).ok_or_else(|| {
            format!(
                "{label} usa o parser desconhecido '{}'; parsers registrados: {}",
                manifest.parser.trim(),
                registered_parsers()
            )
        })?;
        if self.find(&manifest.name).is_some() {
            return Err(format!(
                "ferramenta duplicada: '{}' já está registrada no catálogo",
                manifest.name.trim()
            ));
        }
        if manifest.enabled {
            self.tools.push(RegisteredTool {
                manifest: manifest.clone(),
                runner,
                parser,
            });
        }
        Ok(())
    }
}

fn nmap_manifest() -> ToolManifest {
    ToolManifest {
        name: "Nmap".to_string(),
        description: "Mapeamento de hosts, portas e serviços".to_string(),
        category: "RECON".to_string(),
        image: NMAP_IMAGE.to_string(),
        version: NMAP_VERSION.to_string(),
        runner: RUNNER_NMAP.to_string(),
        parser: PARSER_NMAP_XML.to_string(),
        command_template: vec![
            "nmap".to_string(),
            "-Pn".to_string(),
            "-sT".to_string(),
            "-sV".to_string(),
            "-oX".to_string(),
            "-".to_string(),
            "{target}".to_string(),
        ],
        output_format: "xml".to_string(),
        enabled: true,
    }
}

fn nuclei_manifest() -> ToolManifest {
    ToolManifest {
        name: "Nuclei".to_string(),
        description: "Scanner de vulnerabilidades (CVEs)".to_string(),
        category: "DAST".to_string(),
        image: NUCLEI_IMAGE.to_string(),
        version: NUCLEI_VERSION.to_string(),
        runner: RUNNER_NUCLEI.to_string(),
        parser: PARSER_NUCLEI_JSONL.to_string(),
        command_template: vec![
            "nuclei".to_string(),
            "-u".to_string(),
            "{target}".to_string(),
            "-jsonl".to_string(),
            "-silent".to_string(),
        ],
        output_format: "jsonl".to_string(),
        enabled: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::persistence::PersistedConfig;
    use crate::config::Configuration;

    fn generic_manifest(name: &str) -> ToolManifest {
        ToolManifest {
            name: name.to_string(),
            description: "Ferramenta de exemplo".to_string(),
            category: "DAST".to_string(),
            image: "example/tool:1".to_string(),
            version: "1.0".to_string(),
            runner: RUNNER_GENERIC.to_string(),
            parser: PARSER_GENERIC_TEXT.to_string(),
            command_template: vec!["tool".to_string(), "-u".to_string(), "{target}".to_string()],
            output_format: "text".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn builtin_catalog_maps_nmap_and_nuclei_to_registered_kinds() {
        let registry = ToolRegistry::builtin();

        let nmap = registry.find("nmap").unwrap();
        assert_eq!(nmap.manifest.name, "Nmap");
        assert_eq!(nmap.runner, RunnerKind::Nmap);
        assert_eq!(nmap.parser, ParserKind::NmapXml);

        let nuclei = registry.find("Nuclei").unwrap();
        assert_eq!(nuclei.runner, RunnerKind::Nuclei);
        assert_eq!(nuclei.parser, ParserKind::NucleiJsonl);
        assert!(registry.errors().is_empty());
    }

    #[test]
    fn registers_a_tool_declared_in_toml_configuration() {
        let persisted: PersistedConfig = toml::from_str(
            "target_url = \"http://test.local\"\n\
             [llm]\nprovider = \"ollama\"\n\
             [[tools]]\n\
             name = \"Nikto\"\n\
             description = \"Scanner de servidores web\"\n\
             category = \"DAST\"\n\
             image = \"docker.io/sullo/nikto:2.5.0\"\n\
             version = \"2.5.0\"\n\
             runner = \"generic\"\n\
             parser = \"generic-text\"\n\
             command_template = [\"nikto\", \"-host\", \"{target}\"]\n\
             output_format = \"text\"\n",
        )
        .unwrap();
        let config = Configuration::from(persisted);
        let registry = ToolRegistry::with_configured(&config.tools).unwrap();

        let nikto = registry.find("nikto").unwrap();
        assert_eq!(nikto.runner, RunnerKind::Generic);
        assert_eq!(nikto.parser, ParserKind::GenericText);
        assert_eq!(nikto.manifest.version, "2.5.0");
    }

    #[test]
    fn rejects_a_tool_duplicated_from_the_builtin_catalog() {
        let error = ToolRegistry::with_configured(&[generic_manifest("nmap")]).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("duplicada"), "{message}");
        assert!(message.contains("nmap"), "{message}");
    }

    #[test]
    fn rejects_duplicated_configured_tools() {
        let error =
            ToolRegistry::with_configured(&[generic_manifest("Nikto"), generic_manifest("nikto")])
                .unwrap_err();

        assert!(error.to_string().contains("duplicada"), "{error}");
    }

    #[test]
    fn rejects_an_unknown_runner_citing_the_tool_and_the_field() {
        let mut manifest = generic_manifest("Nikto");
        manifest.runner = "runner-inexistente".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Nikto"), "{message}");
        assert!(message.contains("runner desconhecido"), "{message}");
        assert!(message.contains("runner-inexistente"), "{message}");
        assert!(message.contains("nmap"), "{message}");
    }

    #[test]
    fn rejects_an_unknown_parser_citing_the_tool_and_the_field() {
        let mut manifest = generic_manifest("Nikto");
        manifest.parser = "parser-inexistente".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Nikto"), "{message}");
        assert!(message.contains("parser desconhecido"), "{message}");
        assert!(message.contains("generic-text"), "{message}");
    }

    #[test]
    fn rejects_a_missing_required_field_citing_the_tool() {
        let mut manifest = generic_manifest("Nikto");
        manifest.image.clear();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Nikto"), "{message}");
        assert!(message.contains("'image'"), "{message}");
    }

    #[test]
    fn a_disabled_tool_stays_out_of_the_catalog() {
        let mut manifest = generic_manifest("Nikto");
        manifest.enabled = false;

        let registry = ToolRegistry::with_configured(&[manifest]).unwrap();

        assert!(registry.find("Nikto").is_none());
    }
}
