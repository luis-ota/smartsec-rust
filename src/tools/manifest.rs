use serde::{Deserialize, Serialize};

/// Marcador substituído pelo alvo real dentro de `command_template`.
pub const TARGET_PLACEHOLDER: &str = "{target}";

const IMAGE_HINT: &str = "use 'registry/nome:tag' ou 'nome@sha256:<digest>', sem opções do Podman";

fn is_valid_image_reference(image: &str) -> bool {
    let name = match image.split_once('@') {
        Some((name, digest)) => {
            let Some((algorithm, value)) = digest.split_once(':') else {
                return false;
            };
            if algorithm.is_empty()
                || !algorithm
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.'))
            {
                return false;
            }
            if value.len() < 32 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
            name
        }
        None => image,
    };
    let segment_start = name.rfind('/').map_or(0, |index| index + 1);
    let (name, tag) = match name[segment_start..].find(':') {
        Some(offset) => {
            let index = segment_start + offset;
            (&name[..index], Some(&name[index + 1..]))
        }
        None => (name, None),
    };
    if let Some(tag) = tag {
        if !is_valid_tag(tag) {
            return false;
        }
    }
    let components: Vec<&str> = name.split('/').collect();
    if components.is_empty() {
        return false;
    }
    components
        .iter()
        .enumerate()
        .all(|(index, component)| is_valid_component(component, index == 0))
}

fn is_valid_tag(tag: &str) -> bool {
    if tag.is_empty() || tag.len() > 128 {
        return false;
    }
    let mut characters = tag.chars();
    let first = characters.next().unwrap_or_default();
    (first.is_ascii_alphanumeric() || first == '_')
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_valid_component(component: &str, allow_registry_port: bool) -> bool {
    let mut characters = component.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && component.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-')
                || (allow_registry_port && c == ':')
        })
}

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
        self.validate_image(&label)?;
        if self.command_template.is_empty() {
            return Err(format!(
                "{label} não define o campo obrigatório 'command_template' em [[tools]]"
            ));
        }
        for (index, argument) in self.command_template.iter().enumerate() {
            if argument.trim().is_empty() {
                return Err(format!(
                    "{label}: 'command_template' não pode conter item vazio (item {})",
                    index + 1
                ));
            }
        }
        let executable = self
            .command_template
            .first()
            .map(|argument| argument.trim())
            .unwrap_or_default();
        if executable.starts_with('-') {
            return Err(format!(
                "{label}: o primeiro item de 'command_template' deve ser o executável e não pode começar com '-'"
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

    /// Bloqueia valores de `image` que virariam opções do Podman (`--privileged`,
    /// `--volume`, ...) ou referências inválidas.
    fn validate_image(&self, label: &str) -> Result<(), String> {
        let image = self.image.trim();
        if image
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(format!(
                "{label}: o campo 'image' não pode conter espaços nem caracteres de controle; {IMAGE_HINT}"
            ));
        }
        if image.starts_with('-') {
            return Err(format!(
                "{label}: o campo 'image' não pode começar com '-' porque o Podman o interpretaria como opção; {IMAGE_HINT}"
            ));
        }
        if !is_valid_image_reference(image) {
            return Err(format!(
                "{label}: o campo 'image' deve ser uma referência de imagem válida; {IMAGE_HINT}"
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
    fn rejects_image_that_would_be_a_podman_option() {
        for image in ["--privileged", "--volume", "--volume=/:/host:rw", "-v"] {
            let mut manifest = manifest();
            manifest.image = image.to_string();

            let error = manifest.validate(0).unwrap_err();

            assert!(error.contains("Ferramenta"), "{image}: {error}");
            assert!(error.contains("image"), "{image}: {error}");
            assert!(error.contains("Podman"), "{image}: {error}");
        }
    }

    #[test]
    fn rejects_invalid_image_references() {
        for image in [
            "",
            "   ",
            "alpine --privileged",
            "foo/bar baz",
            "alpine:",
            "/alpine",
            "foo//bar",
            "foo/--bar",
            "alpine@sha256:xyz",
        ] {
            let mut manifest = manifest();
            manifest.image = image.to_string();

            assert!(
                manifest.validate(0).is_err(),
                "imagem inválida aceita: {image:?}"
            );
        }
    }

    #[test]
    fn accepts_common_image_references() {
        for image in [
            "alpine",
            "alpine:3.20",
            "localhost:5000/nikto:2.5.0",
            "docker.io/instrumentisto/nmap:7.95",
            "docker.io/projectdiscovery/nuclei@sha256:2a11faa83464d769a888f1abb9396d5b4d8640619dfc6310086bf5c0d4003481",
            "example/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let mut manifest = manifest();
            manifest.image = image.to_string();

            assert!(manifest.validate(0).is_ok(), "imagem válida rejeitada: {image}");
        }
    }

    #[test]
    fn rejects_empty_item_and_flag_first_in_command_template() {
        let mut tool = manifest();
        tool.command_template = vec![
            "tool".to_string(),
            String::new(),
            TARGET_PLACEHOLDER.to_string(),
        ];
        let error = tool.validate(0).unwrap_err();
        assert!(error.contains("item vazio"), "{error}");

        let mut tool = manifest();
        tool.command_template = vec!["--privileged".to_string(), TARGET_PLACEHOLDER.to_string()];
        let error = tool.validate(0).unwrap_err();
        assert!(error.contains("primeiro item"), "{error}");
        assert!(error.contains("executável"), "{error}");

        let mut tool = manifest();
        tool.command_template = vec!["   ".to_string(), TARGET_PLACEHOLDER.to_string()];
        assert!(tool.validate(0).unwrap_err().contains("item vazio"));
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
