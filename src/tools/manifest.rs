use serde::{Deserialize, Serialize};

/// Marcador substituído pelo alvo real dentro de `command_template`.
pub const TARGET_PLACEHOLDER: &str = "{target}";

/// Manifesto de uma ferramenta de segurança.
///
/// O manifesto é a única fonte de metadados do catálogo: nome exibido,
/// descrição, categoria, imagem, versão, runner, parser, comando e formato de
/// saída. Ferramentas embutidas são construídas pelo `ToolRegistry`; novas
/// ferramentas entram pela chave `[[tools]]` do arquivo de configuração TOML.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ToolManifest {
    pub name: String,
    pub description: String,
    pub category: String,
    pub image: String,
    pub version: String,
    pub runner: String,
    pub parser: String,
    pub command_template: Vec<String>,
    pub output_format: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Default for ToolManifest {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            category: String::new(),
            image: String::new(),
            version: String::new(),
            runner: String::new(),
            parser: String::new(),
            command_template: Vec::new(),
            output_format: String::new(),
            enabled: true,
        }
    }
}

impl ToolManifest {
    /// Valida os campos obrigatórios com mensagem acionável em pt-BR.
    ///
    /// `position` é o índice da entrada em `[[tools]]`, usado para identificar
    /// a ferramenta mesmo quando o próprio campo `name` está ausente.
    pub fn validate(&self, position: usize) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err(format!(
                "a ferramenta #{} de [[tools]] não define o campo obrigatório 'name'",
                position + 1
            ));
        }
        let label = format!("a ferramenta '{}'", self.name.trim());
        for (field, value) in [
            ("description", self.description.as_str()),
            ("category", self.category.as_str()),
            ("image", self.image.as_str()),
            ("version", self.version.as_str()),
            ("runner", self.runner.as_str()),
            ("parser", self.parser.as_str()),
            ("output_format", self.output_format.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "{label} não define o campo obrigatório '{field}' em [[tools]]"
                ));
            }
        }
        if self.command_template.is_empty() {
            return Err(format!(
                "{label} não define o campo obrigatório 'command_template' em [[tools]]"
            ));
        }
        if !self
            .command_template
            .iter()
            .any(|argument| argument.contains(TARGET_PLACEHOLDER))
        {
            return Err(format!(
                "{label}: 'command_template' deve conter o marcador {TARGET_PLACEHOLDER}"
            ));
        }
        Ok(())
    }

    /// Materializa o comando do container substituindo `{target}` pelo alvo.
    pub fn render_command(&self, target: &str) -> Vec<String> {
        self.command_template
            .iter()
            .map(|argument| argument.replace(TARGET_PLACEHOLDER, target))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ToolManifest {
        ToolManifest {
            name: "Ferramenta".to_string(),
            description: "Descrição".to_string(),
            category: "DAST".to_string(),
            image: "example/tool:1".to_string(),
            version: "1.0".to_string(),
            runner: "generic".to_string(),
            parser: "generic-text".to_string(),
            command_template: vec![
                "tool".to_string(),
                "-u".to_string(),
                TARGET_PLACEHOLDER.to_string(),
            ],
            output_format: "text".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn renders_the_target_placeholder() {
        let rendered = manifest().render_command("http://alvo.local:8080");

        assert_eq!(rendered, ["tool", "-u", "http://alvo.local:8080"]);
    }

    #[test]
    fn enabled_is_true_by_default() {
        let parsed: ToolManifest = toml::from_str("name = \"Ferramenta\"").unwrap();

        assert!(parsed.enabled);
    }

    #[test]
    fn rejects_a_template_without_the_target_placeholder() {
        let mut manifest = manifest();
        manifest.command_template = vec!["tool".to_string()];

        let error = manifest.validate(0).unwrap_err();

        assert!(error.contains("command_template"), "{error}");
        assert!(error.contains(TARGET_PLACEHOLDER), "{error}");
    }

    #[test]
    fn rejects_a_missing_field_citing_the_tool_and_the_field() {
        let mut manifest = manifest();
        manifest.version.clear();

        let error = manifest.validate(0).unwrap_err();

        assert!(error.contains("Ferramenta"), "{error}");
        assert!(error.contains("version"), "{error}");
    }
}
