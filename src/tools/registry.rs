use crate::tools::manifest::{ToolManifest, TARGET_PLACEHOLDER};
use crate::tools::nikto::{NIKTO_IMAGE, NIKTO_VERSION};
use crate::tools::nmap::{NMAP_IMAGE, NMAP_VERSION};
use crate::tools::nuclei::{NUCLEI_IMAGE, NUCLEI_VERSION};
use crate::tools::sqlmap::{SQLMAP_IMAGE, SQLMAP_VERSION};
use crate::tools::trufflehog::{TRUFFLEHOG_IMAGE, TRUFFLEHOG_VERSION};
use crate::tools::zap::{ZAP_IMAGE, ZAP_VERSION};

/// Runners registrados: executam o manifesto dentro do executor Podman rootless.
pub const RUNNER_NMAP: &str = "nmap";
pub const RUNNER_NUCLEI: &str = "nuclei";
pub const RUNNER_GENERIC: &str = "generic";
/// Runner que monta o alvo dentro do container, em modo somente leitura.
///
/// Diferente do `generic`, que não recebe mount algum, o `repository` canonicaliza
/// o diretório do repositório e o monta em `:ro`, porque o scanner precisa ler um
/// repositório que vive no host.
pub const RUNNER_REPOSITORY: &str = "repository";
/// Runner do ZAP: monta o plano de automação e coleta o relatório gravado pelo container.
pub const RUNNER_ZAP: &str = "zap";

/// Parsers registrados: convertem a saída de um runner em achados.
pub const PARSER_NMAP_XML: &str = "nmap-xml";
pub const PARSER_NUCLEI_JSONL: &str = "nuclei-jsonl";
pub const PARSER_GENERIC_TEXT: &str = "generic-text";
/// Parser do relatório JSON do Nikto.
pub const PARSER_NIKTO_JSON: &str = "nikto-json";
/// Parser do texto do SQLMap.
pub const PARSER_SQLMAP_TEXT: &str = "sqlmap-text";
/// Parser do JSONL emitido pelo TruffleHog.
pub const PARSER_TRUFFLEHOG_JSONL: &str = "trufflehog-jsonl";
/// Parser do relatório `traditional-json` do OWASP ZAP.
pub const PARSER_ZAP_JSON: &str = "zap-json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerKind {
    Nmap,
    Nuclei,
    Generic,
    Repository,
    Zap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserKind {
    NmapXml,
    NucleiJsonl,
    GenericText,
    NiktoJson,
    SqlmapText,
    TruffleHogJsonl,
    ZapJson,
}

fn runner_kind(runner: &str) -> Option<RunnerKind> {
    match runner.trim() {
        RUNNER_NMAP => Some(RunnerKind::Nmap),
        RUNNER_NUCLEI => Some(RunnerKind::Nuclei),
        RUNNER_GENERIC => Some(RunnerKind::Generic),
        RUNNER_REPOSITORY => Some(RunnerKind::Repository),
        RUNNER_ZAP => Some(RunnerKind::Zap),
        _ => None,
    }
}

fn parser_kind(parser: &str) -> Option<ParserKind> {
    match parser.trim() {
        PARSER_NMAP_XML => Some(ParserKind::NmapXml),
        PARSER_NUCLEI_JSONL => Some(ParserKind::NucleiJsonl),
        PARSER_GENERIC_TEXT => Some(ParserKind::GenericText),
        PARSER_NIKTO_JSON => Some(ParserKind::NiktoJson),
        PARSER_SQLMAP_TEXT => Some(ParserKind::SqlmapText),
        PARSER_TRUFFLEHOG_JSONL => Some(ParserKind::TruffleHogJsonl),
        PARSER_ZAP_JSON => Some(ParserKind::ZapJson),
        _ => None,
    }
}

fn registered_runners() -> String {
    [
        RUNNER_NMAP,
        RUNNER_NUCLEI,
        RUNNER_GENERIC,
        RUNNER_REPOSITORY,
    ]
    .join(", ")
    [RUNNER_NMAP, RUNNER_NUCLEI, RUNNER_GENERIC, RUNNER_ZAP].join(", ")
}

fn registered_parsers() -> String {
    [
        PARSER_NMAP_XML,
        PARSER_NUCLEI_JSONL,
        PARSER_GENERIC_TEXT,
        PARSER_NIKTO_JSON,
        PARSER_SQLMAP_TEXT,
        PARSER_TRUFFLEHOG_JSONL,
        PARSER_ZAP_JSON,
    ]
    .join(", ")
}

fn expected_output_format(parser: ParserKind) -> &'static str {
    match parser {
        ParserKind::NmapXml => "xml",
        ParserKind::NucleiJsonl => "jsonl",
        ParserKind::GenericText => "text",
        ParserKind::NiktoJson => "json",
        ParserKind::SqlmapText => "text",
        ParserKind::TruffleHogJsonl => "jsonl",
        ParserKind::ZapJson => "json",
    }
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
        registry.push_builtin(nikto_manifest(), RunnerKind::Generic, ParserKind::NiktoJson);
        registry.push_builtin(
            sqlmap_manifest(),
            RunnerKind::Generic,
            ParserKind::SqlmapText,
            trufflehog_manifest(),
            RunnerKind::Repository,
            ParserKind::TruffleHogJsonl,
        );
        registry.push_builtin(zap_manifest(), RunnerKind::Zap, ParserKind::ZapJson);
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
        let expected_format = expected_output_format(parser);
        if !manifest
            .output_format
            .trim()
            .eq_ignore_ascii_case(expected_format)
        {
            return Err(format!(
                "{label}: 'output_format' deve ser '{expected_format}' para o parser '{}'; encontrado '{}'",
                manifest.parser.trim(),
                manifest.output_format.trim()
            ));
        }
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

/// Manifesto embutido do Nikto.
///
/// Usa o runner `generic`: o `command_template` abaixo é o comando validado
/// empiricamente no container (ver `docs/evidence/issue-14-nikto.md`), sem
/// shell, com `-o -` para escrever o JSON no stdout e `-ask no` para impedir
/// que o prompt do CIRT.net contamine a saída.
fn nikto_manifest() -> ToolManifest {
    ToolManifest {
        name: "Nikto".to_string(),
        description: "Scanner de configuração de servidores web".to_string(),
        category: "DAST".to_string(),
        image: NIKTO_IMAGE.to_string(),
        version: NIKTO_VERSION.to_string(),
        runner: RUNNER_GENERIC.to_string(),
        parser: PARSER_NIKTO_JSON.to_string(),
        command_template: crate::tools::nikto::container_arguments(TARGET_PLACEHOLDER),
        output_format: "json".to_string(),
        enabled: true,
    }
}

/// Manifesto embutido do SQLMap.
///
/// Usa o runner `generic`: o `command_template` abaixo é o comando validado
/// empiricamente no container (ver `docs/evidence/issue-15-sqlmap.md`), sem
/// shell e sem arquivo. O SQLMap não tem modo JSON, então o `output_format` é
/// `text` e o resultado é lido do stdout.
fn sqlmap_manifest() -> ToolManifest {
    ToolManifest {
        name: "SQLMap".to_string(),
        description: "Scanner de injeção SQL em aplicações web".to_string(),
        category: "DAST".to_string(),
        image: SQLMAP_IMAGE.to_string(),
        version: SQLMAP_VERSION.to_string(),
        runner: RUNNER_GENERIC.to_string(),
        parser: PARSER_SQLMAP_TEXT.to_string(),
        command_template: crate::tools::sqlmap::container_arguments(TARGET_PLACEHOLDER),
        output_format: "text".to_string(),
/// Manifesto embutido do TruffleHog.
///
/// Usa o runner `repository`: o `command_template` abaixo é o comando validado
/// empiricamente no container (ver `docs/evidence/issue-18-trufflehog.md`), sem
/// shell, com `--json` porque sem ele o TruffleHog imprime o valor do segredo em
/// claro no stdout. O `{target}` é substituído pela URI resolvida pelo runner:
/// `file:///alvo` para repositório local montado em somente leitura, ou a URI
/// remota autorizada.
fn trufflehog_manifest() -> ToolManifest {
    ToolManifest {
        name: "TruffleHog".to_string(),
        description: "Detecção de segredos expostos em repositórios".to_string(),
        category: "SECRETS".to_string(),
        image: TRUFFLEHOG_IMAGE.to_string(),
        version: TRUFFLEHOG_VERSION.to_string(),
        runner: RUNNER_REPOSITORY.to_string(),
        parser: PARSER_TRUFFLEHOG_JSONL.to_string(),
        // O `{target}` é a URI resolvida pelo runner: `file:///alvo` para
        // repositório local montado em somente leitura, ou a URI remota
        // autorizada. O mount em si é aplicado pelo executor, fora do comando.
        // Passar o placeholder com montagem vazia devolve exatamente a mesma
        // lista de `container_arguments`, com o marcador no lugar da URI.
        command_template: crate::tools::trufflehog::container_arguments(TARGET_PLACEHOLDER, ""),
        output_format: "jsonl".to_string(),
/// Manifesto embutido do OWASP ZAP.
///
/// O job `report` do ZAP sempre acrescenta a extensão do template ao nome do
/// arquivo, então o relatório nunca vai para o stdout: o runner `zap` monta o
/// plano de automação em memória, monta-o em somente leitura e coleta o
/// relatório gravado no diretório de saída (ver
/// `docs/evidence/issue-28-zap.md`).
fn zap_manifest() -> ToolManifest {
    ToolManifest {
        name: "ZAP".to_string(),
        description: "Scanner dinâmico de segurança de aplicações web".to_string(),
        category: "DAST".to_string(),
        image: ZAP_IMAGE.to_string(),
        version: ZAP_VERSION.to_string(),
        runner: RUNNER_ZAP.to_string(),
        parser: PARSER_ZAP_JSON.to_string(),
        command_template: crate::tools::zap::container_arguments(TARGET_PLACEHOLDER),
        output_format: "json".to_string(),
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
    fn builtin_catalog_exposes_nikto_with_pinned_image_and_version() {
        let registry = ToolRegistry::builtin();

        let nikto = registry
            .find("nikto")
            .expect("o Nikto deve estar no catálogo embutido");

        assert_eq!(nikto.manifest.name, "Nikto");
        assert_eq!(nikto.parser, ParserKind::NiktoJson);
        assert_eq!(nikto.runner, RunnerKind::Generic);
        assert_eq!(nikto.manifest.output_format, "json");
        assert!(nikto.manifest.enabled);

        // Imagem fixada por digest e versão registrada para o log estruturado.
        assert!(
            nikto.manifest.image.contains("@sha256:"),
            "{}",
            nikto.manifest.image
        );
        assert_eq!(nikto.manifest.version, "2.1.6");
    }

    #[test]
    fn builtin_nikto_command_template_avoids_shell_and_targets_the_placeholder() {
        let registry = ToolRegistry::builtin();
        let nikto = registry.find("nikto").unwrap();

        // O manifesto embutido passa pela mesma validação das ferramentas do TOML.
        assert!(nikto.manifest.validate(0).is_ok());

        let command = nikto.manifest.render_command("http://169.254.1.2:3000");

        assert_eq!(command.first().map(String::as_str), Some("nikto.pl"));
        assert!(command.contains(&"http://169.254.1.2:3000".to_string()));
        // Nenhum item do comando introduz metacaractere de shell.
        for argument in &command {
            assert!(
                !argument.contains(['|', '>', '<', ';', '$', '&', '`']),
                "{argument}"
            );
        }
        // Nenhum placeholder sobrevive à renderização.
        assert!(!command.iter().any(|item| item.contains(TARGET_PLACEHOLDER)));
    }

    #[test]
    fn builtin_catalog_exposes_the_zap_with_pinned_image_version_and_own_runner() {
        let registry = ToolRegistry::builtin();

        let zap = registry
            .find("zap")
            .expect("o ZAP deve estar no catálogo embutido");

        assert_eq!(zap.manifest.name, "ZAP");
        assert_eq!(zap.runner, RunnerKind::Zap);
        assert_eq!(zap.parser, ParserKind::ZapJson);
        assert_eq!(zap.manifest.output_format, "json");
        assert!(zap.manifest.enabled);
        assert!(
            zap.manifest.image.contains("@sha256:"),
            "{}",
            zap.manifest.image
        );
        assert_eq!(zap.manifest.version, "2.14.0");
    }

    #[test]
    fn builtin_zap_command_template_avoids_shell_and_targets_the_placeholder() {
        let registry = ToolRegistry::builtin();
        let zap = registry.find("zap").unwrap();

        // O manifesto embutido passa pela mesma validação das ferramentas do TOML.
        assert!(zap.manifest.validate(0).is_ok());

        let command = zap.manifest.render_command("http://169.254.1.2:3000");

        assert_eq!(command.first().map(String::as_str), Some("zap.sh"));
        assert!(command.iter().any(|item| item == "-Xmx1024m"));
        assert!(command.iter().any(|item| item == "-cmd"));
        assert!(command
            .iter()
            .any(|item| item == "spider.scope=http://169.254.1.2:3000"));
        for argument in &command {
            assert!(
                !argument.contains(['|', '>', '<', ';', '$', '&', '`']),
                "{argument}"
            );
        }
        assert!(!command.iter().any(|item| item.contains(TARGET_PLACEHOLDER)));
    }

    #[test]
    fn a_configured_tool_cannot_reuse_the_builtin_zap_name() {
        let mut manifest = generic_manifest("ZAP");
        manifest.runner = RUNNER_ZAP.to_string();
        manifest.parser = PARSER_ZAP_JSON.to_string();
        manifest.output_format = "json".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("duplicada"), "{message}");
        assert!(message.contains("ZAP"), "{message}");
    }

    #[test]
    fn a_configured_tool_can_use_the_zap_runner_and_parser() {
        let mut manifest = generic_manifest("ZapLegado");
        manifest.runner = RUNNER_ZAP.to_string();
        manifest.parser = PARSER_ZAP_JSON.to_string();
        manifest.output_format = "json".to_string();

        let registry = ToolRegistry::with_configured(&[manifest]).unwrap();

        assert_eq!(
            registry.find("ZapLegado").unwrap().parser,
            ParserKind::ZapJson
        );
    }

    #[test]
    fn the_zap_parser_requires_the_json_output_format() {
        let mut manifest = generic_manifest("ZapWeb");
        manifest.parser = PARSER_ZAP_JSON.to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("output_format"), "{message}");
        assert!(message.contains("'json'"), "{message}");
    }

    #[test]
    fn the_zap_runner_is_listed_in_the_actionable_error_message() {
        let mut manifest = generic_manifest("ZapExterno");
        manifest.runner = "zap".to_owned();
        manifest.parser = PARSER_ZAP_JSON.to_string();
        manifest.output_format = "json".to_string();
        // Sanidade: o runner registrado é aceito quando o resto é válido.
        assert!(ToolRegistry::with_configured(&[manifest.clone()]).is_ok());

        manifest.parser = "parser-inexistente".to_string();
        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        assert!(error.to_string().contains("parser desconhecido"), "{error}");
    }

    #[test]
    fn nikto_is_rejected_when_a_configured_tool_reuses_its_name() {
        let mut manifest = generic_manifest("Nikto");
        manifest.runner = RUNNER_GENERIC.to_string();
        manifest.parser = PARSER_NIKTO_JSON.to_string();
        manifest.output_format = "json".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("duplicada"), "{message}");
        assert!(message.contains("Nikto"), "{message}");
    }

    #[test]
    fn rejects_a_configured_tool_declaring_the_nikto_parser_with_the_wrong_format() {
        let mut manifest = generic_manifest("NiktoWeb");
        manifest.parser = PARSER_NIKTO_JSON.to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("output_format"), "{message}");
        assert!(message.contains("'json'"), "{message}");
        assert!(message.contains(PARSER_NIKTO_JSON), "{message}");
    }

    #[test]
    fn a_configured_tool_can_use_the_nikto_parser() {
        let mut manifest = generic_manifest("NiktoLegado");
        manifest.parser = PARSER_NIKTO_JSON.to_string();
        manifest.output_format = "json".to_string();

        let registry = ToolRegistry::with_configured(&[manifest]).unwrap();

        assert_eq!(
            registry.find("NiktoLegado").unwrap().parser,
            ParserKind::NiktoJson
        );
    }

    #[test]
    fn builtin_catalog_exposes_sqlmap_with_pinned_image_and_version() {
        let registry = ToolRegistry::builtin();

        let sqlmap = registry
            .find("sqlmap")
            .expect("o SQLMap deve estar no catálogo embutido");

        assert_eq!(sqlmap.manifest.name, "SQLMap");
        assert_eq!(sqlmap.parser, ParserKind::SqlmapText);
        assert_eq!(sqlmap.runner, RunnerKind::Generic);
        assert_eq!(sqlmap.manifest.output_format, "text");
        assert!(sqlmap.manifest.enabled);

        // Imagem fixada por digest e versão registrada para o log estruturado.
        assert!(
            sqlmap.manifest.image.contains("@sha256:"),
            "{}",
            sqlmap.manifest.image
        );
        assert_eq!(sqlmap.manifest.version, "1.10.4");
    }

    #[test]
    fn builtin_sqlmap_command_template_is_non_interactive_and_avoids_shell() {
        let registry = ToolRegistry::builtin();
        let sqlmap = registry.find("sqlmap").unwrap();

        // O manifesto embutido passa pela mesma validação das ferramentas do TOML.
        assert!(sqlmap.manifest.validate(0).is_ok());

        let command = sqlmap
            .manifest
            .render_command("http://169.254.1.2:3100/item?id=1");

        assert_eq!(command.first().map(String::as_str), Some("sqlmap"));
        // O alvo só pode aparecer como valor de `-u`, nunca como flag.
        let position = command
            .iter()
            .position(|item| item == "-u")
            .expect("o alvo deve ser informado com -u");
        assert_eq!(command[position + 1], "http://169.254.1.2:3100/item?id=1");
        // Nenhum item do comando introduz metacaractere de shell.
        for argument in &command {
            assert!(
                !argument.contains(['|', '>', '<', ';', '$', '&', '`']),
                "{argument}"
            );
        }
        // Nenhum placeholder sobrevive à renderização.
        assert!(!command.iter().any(|item| item.contains(TARGET_PLACEHOLDER)));
    }

    #[test]
    fn sqlmap_is_rejected_when_a_configured_tool_reuses_its_name() {
        let mut manifest = generic_manifest("SQLMap");
        manifest.parser = PARSER_SQLMAP_TEXT.to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("duplicada"), "{message}");
        assert!(message.contains("SQLMap"), "{message}");
    }

    #[test]
    fn rejects_a_configured_tool_declaring_the_sqlmap_parser_with_the_wrong_format() {
        let mut manifest = generic_manifest("SQLMapLegado");
        manifest.parser = PARSER_SQLMAP_TEXT.to_string();
        manifest.output_format = "json".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("output_format"), "{message}");
        assert!(message.contains("'text'"), "{message}");
        assert!(message.contains(PARSER_SQLMAP_TEXT), "{message}");
    }

    #[test]
    fn a_configured_tool_can_use_the_sqlmap_parser() {
        let mut manifest = generic_manifest("SQLMapLegado");
        manifest.parser = PARSER_SQLMAP_TEXT.to_string();

        let registry = ToolRegistry::with_configured(&[manifest]).unwrap();

        assert_eq!(
            registry.find("SQLMapLegado").unwrap().parser,
            ParserKind::SqlmapText
        );
    }

    #[test]
    fn registers_a_tool_declared_in_toml_configuration() {
        let persisted: PersistedConfig = toml::from_str(
            "target_url = \"http://test.local\"\n\
             [llm]\nprovider = \"ollama\"\n\
             [[tools]]\n\
             name = \"ScannerExemplo\"\n\
             description = \"Scanner de servidores web\"\n\
             category = \"DAST\"\n\
             image = \"example/scanner:2.14.0\"\n\
             version = \"2.14.0\"\n\
             runner = \"generic\"\n\
             parser = \"generic-text\"\n\
             command_template = [\"scanner\", \"-host\", \"{target}\"]\n\
             output_format = \"text\"\n",
        )
        .unwrap();
        let config = Configuration::from(persisted);
        let registry = ToolRegistry::with_configured(&config.tools).unwrap();

        let scanner = registry.find("ScannerExemplo").unwrap();
        assert_eq!(scanner.runner, RunnerKind::Generic);
        assert_eq!(scanner.parser, ParserKind::GenericText);
        assert_eq!(scanner.manifest.version, "2.14.0");
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
            ToolRegistry::with_configured(&[generic_manifest("ScannerExemplo"), generic_manifest("zap")])
                .unwrap_err();
        let error = ToolRegistry::with_configured(&[
            generic_manifest("ScannerExemplo"),
            generic_manifest("zap"),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("duplicada"), "{error}");
    }

    #[test]
    fn rejects_an_unknown_runner_citing_the_tool_and_the_field() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.runner = "runner-inexistente".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("ScannerExemplo"), "{message}");
        assert!(message.contains("runner desconhecido"), "{message}");
        assert!(message.contains("runner-inexistente"), "{message}");
        assert!(message.contains("nmap"), "{message}");
    }

    #[test]
    fn rejects_an_unknown_parser_citing_the_tool_and_the_field() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.parser = "parser-inexistente".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("ScannerExemplo"), "{message}");
        assert!(message.contains("parser desconhecido"), "{message}");
        assert!(message.contains("generic-text"), "{message}");
    }

    #[test]
    fn rejects_a_missing_required_field_citing_the_tool() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.image.clear();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("ScannerExemplo"), "{message}");
        assert!(message.contains("'image'"), "{message}");
    }

    #[test]
    fn rejects_output_format_incompatible_with_the_parser() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.output_format = "xml".to_string();

        let error = ToolRegistry::with_configured(&[manifest]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("ScannerExemplo"), "{message}");
        assert!(message.contains("output_format"), "{message}");
        assert!(message.contains("'text'"), "{message}");
    }

    #[test]
    fn output_format_comparison_is_case_insensitive() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.output_format = "TEXT".to_string();

        assert!(ToolRegistry::with_configured(&[manifest]).is_ok());
    }

    #[test]
    fn a_disabled_tool_stays_out_of_the_catalog() {
        let mut manifest = generic_manifest("ScannerExemplo");
        manifest.enabled = false;

        let registry = ToolRegistry::with_configured(&[manifest]).unwrap();

        assert!(registry.find("ScannerExemplo").is_none());
    }
}
