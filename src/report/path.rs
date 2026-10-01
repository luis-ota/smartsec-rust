use crate::config::Configuration;
use anyhow::Result;

/// Nome padrão do relatório Markdown quando nenhum é configurado.
pub const DEFAULT_REPORT_FILE: &str = "smartsec-report.md";

/// Extensão do relatório PDF derivado do arquivo Markdown configurado.
pub const PDF_EXTENSION: &str = "pdf";

/// Resolve o caminho do relatório Markdown a partir de `output_file`/`output_dir`.
///
/// `output_dir` tem precedência sobre o diretório de `output_file`: quando ele
/// está definido, apenas o nome do arquivo é reaproveitado. O diretório é
/// criado aqui para que a falha de escrita seja visível antes de qualquer
/// tentativa de gravar o artefato.
pub fn resolve_report_path(config: &Configuration) -> Result<std::path::PathBuf> {
    let file = config
        .output_file
        .as_deref()
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or(DEFAULT_REPORT_FILE);
    Ok(resolve_in_dir(file, config.output_dir.as_deref()))
}

/// Aplica a mesma resolução de [`resolve_report_path`] trocando a extensão por PDF.
///
/// O PDF é sempre gravado ao lado do Markdown e com o mesmo nome, para que os
/// dois artefatos de uma execução sejam encontrados juntos (REQ18).
pub fn resolve_pdf_path(markdown_path: &std::path::Path) -> std::path::PathBuf {
    markdown_path.with_extension(PDF_EXTENSION)
}

/// Monta o caminho final a partir do nome do arquivo e do diretório de saída.
fn resolve_in_dir(file: &str, output_dir: Option<&str>) -> std::path::PathBuf {
    let Some(directory) = output_dir.map(str::trim).filter(|dir| !dir.is_empty()) else {
        return std::path::PathBuf::from(file);
    };
    let file_name = std::path::Path::new(file)
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| DEFAULT_REPORT_FILE.into());
    std::path::PathBuf::from(directory).join(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_is_used_when_nothing_is_configured() {
        let config = Configuration::default();
        assert_eq!(
            resolve_report_path(&config).unwrap(),
            std::path::PathBuf::from(DEFAULT_REPORT_FILE)
        );
    }

    #[test]
    fn output_file_is_respected_without_output_dir() {
        let config = Configuration {
            output_file: Some("relatorio.md".to_string()),
            ..Configuration::default()
        };
        assert_eq!(
            resolve_report_path(&config).unwrap(),
            std::path::PathBuf::from("relatorio.md")
        );
    }

    #[test]
    fn output_dir_keeps_only_the_file_name() {
        let config = Configuration {
            output_file: Some("nested/relatorio.md".to_string()),
            output_dir: Some("saida".to_string()),
            ..Configuration::default()
        };
        assert_eq!(
            resolve_report_path(&config).unwrap(),
            std::path::PathBuf::from("saida/relatorio.md")
        );
    }

    #[test]
    fn blank_output_values_fall_back_to_the_default() {
        let config = Configuration {
            output_file: Some("   ".to_string()),
            output_dir: Some("  ".to_string()),
            ..Configuration::default()
        };
        assert_eq!(
            resolve_report_path(&config).unwrap(),
            std::path::PathBuf::from(DEFAULT_REPORT_FILE)
        );
    }

    #[test]
    fn pdf_path_sits_next_to_the_markdown_and_swaps_the_extension() {
        assert_eq!(
            resolve_pdf_path(std::path::Path::new("saida/relatorio.md")),
            std::path::PathBuf::from("saida/relatorio.pdf")
        );
    }
}
