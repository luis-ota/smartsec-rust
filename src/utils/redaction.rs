use serde_json::Value;

const SENSITIVE_KEYS: &[&str] = &[
    "access-key-id",
    "api-key",
    "apikey",
    "authorization",
    "client-secret",
    "cookie",
    "password",
    "private-key",
    "proxy-authorization",
    "secret",
    "secret-access-key",
    "set-cookie",
    "token",
];

const HTTP_PAYLOAD_KEYS: &[&str] = &["curl-command", "request", "response"];

/// Chaves do registro do TruffleHog que carregam o **valor** do segredo.
///
/// Medido em container real: um achado de chave privada chegou ao stdout com
/// `"Raw":"-----BEGIN RSA PRIVATE KEY-----\nMIIE<MASCARADO>…"` e
/// `"SecretParts":{"token":"-----BEGIN RSA PRIVATE KEY-----\n…"}`.
///
/// `Redacted` também sai: ele trunca o segredo no meio e não é estável entre
/// versões, então não serve como evidência nem como registro fiel.
const TRUFFLEHOG_SECRET_KEYS: &[&str] = &["raw", "rawv2", "secretparts", "redacted"];

/// Marcadores que identificam um registro do TruffleHog; as chaves acima só são
/// removidas nesses objetos, sem atingir campo homônimo de outro scanner.
const TRUFFLEHOG_MARKERS: &[&str] = &["detectorname", "sourcemetadata"];

/// Verifica se o objeto é um registro do TruffleHog.
fn is_trufflehog_result(object: &serde_json::Map<String, Value>) -> bool {
    object.keys().any(|key| {
        let key = normalize_key(key);
        TRUFFLEHOG_MARKERS.iter().any(|marker| *marker == key)
    })
}

/// Sanitiza texto técnico antes de exibi-lo ou persistí-lo: registros JSONL
/// perdem requests, responses e curl (que podem carregar credenciais) e linhas
/// com nomes sensíveis são substituídas por inteiro.
pub fn sanitize_text(value: &str) -> String {
    value
        .lines()
        .map(sanitize_line)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn sanitize_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return sanitize_malformed_url(value);
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn sanitize_malformed_url(value: &str) -> String {
    let without_query_or_fragment = value.split(['?', '#']).next().unwrap_or_default();
    let Some((scheme, remainder)) = without_query_or_fragment.split_once("://") else {
        return "[REDACTED]".to_string();
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(authority, path)| (authority, path));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() {
        return "[REDACTED]".to_string();
    }
    if path.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/{path}")
    }
}

pub fn sanitize_evidence_component(value: &str) -> String {
    let sanitized = if value.starts_with("http://") || value.starts_with("https://") {
        sanitize_url(value)
    } else {
        sanitize_text(value)
    };
    sanitized.replace(['\n', '\r', '|'], " ")
}

pub fn sanitize_json_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| !is_http_payload_key(key));
            // O valor do segredo do TruffleHog é removido antes das demais
            // regras, porque é o único caminho em que um segredo detectado
            // poderia chegar a um log, relatório ou finding.
            if is_trufflehog_result(object) {
                object.retain(|key, _| {
                    !TRUFFLEHOG_SECRET_KEYS
                        .iter()
                        .any(|candidate| *candidate == normalize_key(key))
                });
            }
            for (key, child) in object {
                if is_sensitive_key(key) {
                    *child = Value::String("[REDACTED]".to_string());
                } else {
                    sanitize_json_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_json_value(item);
            }
        }
        Value::String(text) => *text = sanitize_string_value(text),
        _ => {}
    }
}

fn sanitize_line(line: &str) -> String {
    let trimmed = line.trim();
    if let Ok(mut json) = serde_json::from_str::<Value>(trimmed) {
        sanitize_json_value(&mut json);
        return serde_json::to_string(&json).unwrap_or_else(|_| "[REDACTED]".to_string());
    }

    sanitize_string_value(line)
}

fn sanitize_string_value(value: &str) -> String {
    let normalized = normalize_key(value);
    if SENSITIVE_KEYS.iter().any(|key| normalized.contains(key))
        || HTTP_PAYLOAD_KEYS.iter().any(|key| normalized.contains(key))
    {
        return "[REDACTED]".to_string();
    }
    sanitize_embedded_url(value)
}

/// Sanitiza um diagnóstico produzido pelo próprio SmartSec, não pela saída de um
/// scanner: a substituição integral de linhas existe para descartar corpos HTTP
/// e curl que só o scanner produz, mas no transporte destruiria o campo — o erro
/// típico "error sending request for url (...)" contém "request" e viraria
/// `[REDACTED]` inteiro. Aqui a credencial e a query string continuam removidas.
pub fn sanitize_diagnostic(value: &str) -> String {
    value
        .lines()
        .map(|line| {
            let normalized = normalize_key(line);
            if SENSITIVE_KEYS.iter().any(|key| normalized.contains(key)) {
                return "[REDACTED]".to_string();
            }
            sanitize_embedded_url(line)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_embedded_url(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            let (prefix, candidate, suffix) = split_url_token(token);
            if candidate.starts_with("http://") || candidate.starts_with("https://") {
                format!("{prefix}{}{suffix}", sanitize_url(candidate))
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn split_url_token(token: &str) -> (&str, &str, &str) {
    let prefix_len = token
        .char_indices()
        .take_while(|(_, character)| matches!(character, '(' | '[' | '<' | '"' | '\''))
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    let suffix_start = token
        .char_indices()
        .rev()
        .take_while(|(_, character)| matches!(character, ')' | ']' | '>' | '"' | '\'' | ',' | ';'))
        .map(|(index, _)| index)
        .last()
        .unwrap_or(token.len());
    if suffix_start < prefix_len {
        return ("", token, "");
    }
    (
        &token[..prefix_len],
        &token[prefix_len..suffix_start],
        &token[suffix_start..],
    )
}

fn normalize_key(value: &str) -> String {
    value.to_ascii_lowercase().replace(['_', ' '], "-")
}

/// Sanitiza uma linha de código para a prévia local da TUI.
///
/// Preserva recuo, sintaxe e nomes de variáveis; mascara apenas valores de
/// chaves sensíveis e credenciais em URLs. Não é usado em logs nem no prompt.
pub fn sanitize_code_line(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .replace('\t', "    ");
    let mut output = String::with_capacity(clean.len());
    let mut rest = clean.as_str();
    while !rest.is_empty() {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (token, tail) = rest.split_at(end);
        let (prefix, candidate, suffix) = split_url_token(token);
        if candidate.starts_with("http://") || candidate.starts_with("https://") {
            output.push_str(prefix);
            output.push_str(&sanitize_url(candidate));
            output.push_str(suffix);
        } else {
            output.push_str(token);
        }
        let whitespace_end = tail
            .find(|character: char| !character.is_whitespace())
            .unwrap_or(tail.len());
        output.push_str(&tail[..whitespace_end]);
        rest = &tail[whitespace_end..];
    }
    mask_code_assignment(&output)
}

/// Sanitiza texto corrido gerado pela IA.
///
/// `sanitize_text` redige a linha inteira ao encontrar "token" ou
/// "authorization", o que apagava explicações legítimas sobre cabeçalhos. Aqui
/// só o valor depois de `chave=`/`chave:` é mascarado; a prosa permanece.
pub fn sanitize_prose(value: &str) -> String {
    value
        .lines()
        .map(sanitize_prose_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn sanitize_prose_line(line: &str) -> String {
    let clean: String = line
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect();
    let mut output = String::new();
    let mut rest = clean.as_str();
    let mut redact_next = 0usize;
    while !rest.is_empty() {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (token, tail) = rest.split_at(end);
        let whitespace_end = tail
            .find(|character: char| !character.is_whitespace())
            .unwrap_or(tail.len());
        if redact_next > 0 {
            output.push_str("[REDACTED]");
            redact_next -= 1;
        } else if let Some((key, _)) = token.split_once(['=', ':']) {
            let key = key.trim();
            if is_sensitive_key(key) {
                let separator = &token[key.len()..key.len() + 1];
                output.push_str(key);
                output.push_str(separator);
                output.push_str("[REDACTED]");
                if key.eq_ignore_ascii_case("authorization") {
                    redact_next = 2;
                }
            } else {
                output.push_str(token);
            }
        } else {
            output.push_str(token);
        }
        output.push_str(&tail[..whitespace_end]);
        rest = &tail[whitespace_end..];
    }
    sanitize_urls_preserving_spaces(&output)
}

fn sanitize_urls_preserving_spaces(value: &str) -> String {
    let mut output = String::new();
    let mut rest = value;
    while !rest.is_empty() {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (token, tail) = rest.split_at(end);
        let (prefix, candidate, suffix) = split_url_token(token);
        if candidate.starts_with("http://") || candidate.starts_with("https://") {
            output.push_str(prefix);
            output.push_str(&sanitize_url(candidate));
            output.push_str(suffix);
        } else {
            output.push_str(token);
        }
        let whitespace_end = tail
            .find(|character: char| !character.is_whitespace())
            .unwrap_or(tail.len());
        output.push_str(&tail[..whitespace_end]);
        rest = &tail[whitespace_end..];
    }
    output
}

fn mask_code_assignment(line: &str) -> String {
    let Some(separator) = line.find(['=', ':']) else {
        return line.to_string();
    };
    let identifier = line[..separator]
        .trim_end()
        .rsplit(|character: char| {
            !(character.is_alphanumeric() || character == '_' || character == '-')
        })
        .next()
        .unwrap_or("");
    if !is_sensitive_key(identifier) {
        return line.to_string();
    }
    let after = &line[separator + 1..];
    let value_start = after.len() - after.trim_start().len();
    let value = &after[value_start..];
    let prefix_end = separator + 1 + value_start;
    if let Some(quote @ ('"' | '\'')) = value.chars().next() {
        if let Some(close) = value[1..].rfind(quote) {
            return format!(
                "{}[REDACTED]{}{}",
                &line[..prefix_end + quote.len_utf8()],
                quote,
                &value[close + 2..]
            );
        }
    }
    format!("{}[REDACTED]", &line[..prefix_end])
}

fn is_sensitive_key(key: &str) -> bool {
    let key = normalize_key(key);
    SENSITIVE_KEYS
        .iter()
        .any(|candidate| key == *candidate || key.ends_with(&format!("-{candidate}")))
}

fn is_http_payload_key(key: &str) -> bool {
    let key = normalize_key(key);
    HTTP_PAYLOAD_KEYS.iter().any(|candidate| key == *candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_http_payloads_and_redacts_nested_secrets_from_jsonl() {
        let raw = r#"{"template-id":"headers","request":"Authorization: Bearer secret","response":"Set-Cookie: session=secret","url":"http://target.local/path?token=secret","metadata":{"api_key":"secret","access_token":"secret","client_secret":"secret","x-api-key":"secret","note":"Authorization: Bearer secret","safe":"value"}}"#;

        let sanitized = sanitize_text(raw);

        assert!(sanitized.contains("\"template-id\":\"headers\""));
        assert!(sanitized.contains("\"safe\":\"value\""));
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("request"));
        assert!(!sanitized.contains("response"));
        assert!(!sanitized.contains(":\"secret\""));
        assert!(!sanitized.contains("Bearer secret"));
        assert!(!sanitized.contains("?token="));
    }

    #[test]
    fn masks_aws_access_key_and_secret_in_code_previews() {
        for line in [
            "AWS_ACCESS_KEY_ID = \"AKIAQ7Z3X5V2N4M6P8R2\"",
            "AWS_SECRET_ACCESS_KEY = \"kR9mQ2xT7vL4pN8sW3yB6cF1hJ5dG0zA\"",
        ] {
            let sanitized = sanitize_code_line(line);
            assert!(
                !sanitized.contains("AKIAQ7Z3") && !sanitized.contains("kR9mQ2xT"),
                "{sanitized}"
            );
        }
    }

    #[test]
    fn removes_credentials_query_and_fragment_from_urls() {
        assert_eq!(
            sanitize_url("https://user:pass@example.com/path?token=secret#fragment"),
            "https://example.com/path"
        );
        assert_eq!(
            sanitize_url("http://user:secret@target.local/%zz?token=secret#fragment"),
            "http://target.local/%zz"
        );
    }

    #[test]
    fn removes_the_trufflehog_secret_fields_from_jsonl() {
        // Registro real do TruffleHog: o segredo está em Raw, RawV2, Redacted
        // e SecretParts, e não pode sobreviver à sanitização.
        let raw = concat!(
            r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/alvo/config/credenciais.env","line":14}}},"SourceID":1,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AWS_SECRET_DE_EXEMPLO_NAO_E_REAL_0000","RawV2":"AWS_SECRET_DE_EXEMPLO_NAO_E_REAL_0000","Redacted":"AWS_SECRET_DE","ExtraData":{},"SecretParts":{"token":"AWS_SECRET_DE_EXEMPLO_NAO_E_REAL_0000"}}"#,
            "\n",
            r#"{"SourceMetadata":{"Data":{"Git":{"file":"src/lib.rs","line":42,"commit":"abc1234","repository":"https://github.com/org/repo"}}},"DetectorName":"PrivateKey","Verified":false,"Raw":"AWS_SECRET_DE_EXEMPLO_NAO_E_REAL_0000"}"#,
            "\n"
        );

        let sanitized = sanitize_text(raw);

        // Detector, arquivo, linha, commit e verificação sobrevivem.
        assert!(
            sanitized.contains("\"DetectorName\":\"AWS\""),
            "{sanitized}"
        );
        assert!(sanitized.contains("config/credenciais.env"), "{sanitized}");
        assert!(sanitized.contains("abc1234"), "{sanitized}");
        assert!(sanitized.contains("\"Verified\":true"), "{sanitized}");
        // O valor do segredo não sobrevive em nenhuma forma.
        assert!(!sanitized.contains("AWS_SECRET_DE_EXEMPLO"), "{sanitized}");
        assert!(!sanitized.contains("\"Raw\""), "{sanitized}");
        assert!(!sanitized.contains("RawV2"), "{sanitized}");
        assert!(!sanitized.contains("SecretParts"), "{sanitized}");
        assert!(!sanitized.contains("Redacted"), "{sanitized}");
    }

    #[test]
    fn nao_remove_raw_de_registro_que_nao_e_trufflehog() {
        // `Raw` de outro scanner não é segredo do TruffleHog e não deve ser
        // apagado por uma regra específica desta ferramenta.
        let raw = r#"{"template-id":"custom","Raw":"valor-legitimo-do-outro-scanner"}"#;

        let sanitized = sanitize_text(raw);

        assert!(
            sanitized.contains("valor-legitimo-do-outro-scanner"),
            "{sanitized}"
        );
    }

    #[test]
    fn redacts_sensitive_text_lines() {
        assert_eq!(sanitize_text("Authorization: Bearer secret"), "[REDACTED]");
        assert_eq!(sanitize_text("request: GET /private"), "[REDACTED]");
        assert_eq!(
            sanitize_text("response: Set-Cookie: id=secret"),
            "[REDACTED]"
        );
        assert_eq!(sanitize_text("resultado seguro"), "resultado seguro");
    }

    #[test]
    fn prose_keeps_the_words_and_redacts_only_values() {
        let sanitized = sanitize_prose(
            "O cabeçalho Authorization: Bearer abc123 deve ser configurado. Use token=segredo no header.",
        );

        assert!(!sanitized.contains("abc123"), "{sanitized}");
        assert!(!sanitized.contains("segredo"), "{sanitized}");
        assert!(sanitized.contains("Authorization"), "{sanitized}");
        assert!(sanitized.contains("[REDACTED]"), "{sanitized}");
        assert_eq!(
            sanitize_prose("O token JWT deve ser validado antes do uso."),
            "O token JWT deve ser validado antes do uso."
        );
    }

    #[test]
    fn code_preview_keeps_indentation_and_hides_only_values() {
        assert_eq!(
            sanitize_code_line("    let password = \"segredo\";"),
            "    let password = \"[REDACTED]\";"
        );
        assert_eq!(
            sanitize_code_line("    let request = client.get(url);"),
            "    let request = client.get(url);"
        );
        assert_eq!(
            sanitize_code_line("    let url = \"http://user:pass@host/p?token=segredo\";"),
            "    let url = \"http://host/p\";"
        );
    }
}
