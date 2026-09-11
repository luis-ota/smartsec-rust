use serde_json::Value;

const SENSITIVE_KEYS: &[&str] = &[
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "proxy-authorization",
    "secret",
    "set-cookie",
    "token",
];

const HTTP_PAYLOAD_KEYS: &[&str] = &["curl-command", "request", "response"];

/// Sanitiza texto técnico antes de exibi-lo ou persistí-lo.
///
/// Registros JSONL de scanners preservam os metadados do achado, mas descartam
/// requests, responses e comandos curl, que podem conter corpos, cookies e
/// credenciais do alvo. Linhas textuais com nomes sensíveis são substituídas
/// integralmente para não depender do formato usado por cada ferramenta.
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
    fn redacts_sensitive_text_lines() {
        assert_eq!(sanitize_text("Authorization: Bearer secret"), "[REDACTED]");
        assert_eq!(sanitize_text("request: GET /private"), "[REDACTED]");
        assert_eq!(
            sanitize_text("response: Set-Cookie: id=secret"),
            "[REDACTED]"
        );
        assert_eq!(sanitize_text("resultado seguro"), "resultado seguro");
    }
}
