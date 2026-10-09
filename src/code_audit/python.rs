use crate::code_audit::CodeAuditFinding;
use crate::domain::severity::Severity;

const SQL_CALLS: &[&str] = &["execute", "executemany", "executescript", "executebatch"];

const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_key",
    "private_key",
    "senha",
    "chave",
];

const PLACEHOLDERS: &[&str] = &[
    "getenv",
    "environ",
    "none",
    "changeme",
    "change",
    "example",
    "xxx",
    "...",
    "your",
    "todo",
    "redacted",
    "removed",
    "secretprovider",
];

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Punct(char),
}

impl Token {
    fn is_punct(&self, c: char) -> bool {
        matches!(self, Token::Punct(found) if *found == c)
    }

    fn ident(&self) -> Option<&str> {
        match self {
            Token::Ident(name) => Some(name),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Token::Str(value) => Some(value),
            _ => None,
        }
    }
}

fn tokenize(line: &str) -> Vec<Token> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < chars.len() {
        let c = chars[index];

        if c.is_whitespace() {
            index += 1;
        } else if c == '#' {
            break;
        } else if c == '"' || c == '\'' {
            let quote = c;
            let mut value = String::new();
            let mut cursor = index + 1;
            let mut escaped = false;
            while cursor < chars.len() {
                let current = chars[cursor];
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == quote {
                    break;
                } else {
                    value.push(current);
                }
                cursor += 1;
            }
            let prefix = if index > 0
                && matches!(
                    chars[index - 1],
                    'f' | 'F' | 'b' | 'B' | 'r' | 'R' | 'u' | 'U'
                ) {
                Some(chars[index - 1])
            } else {
                None
            };
            if let Some(marker) = prefix {
                let marker = marker.to_ascii_lowercase();
                if let Some(Token::Ident(name)) = tokens.last_mut() {
                    name.pop();
                }
                tokens.push(Token::Ident(format!("{marker}string")));
            } else {
                tokens.push(Token::Str(value));
            }
            index = cursor + 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = index;
            while index < chars.len() && (chars[index].is_alphanumeric() || chars[index] == '_') {
                index += 1;
            }
            tokens.push(Token::Ident(chars[start..index].iter().collect()));
        } else {
            tokens.push(Token::Punct(c));
            index += 1;
        }
    }
    tokens
}

struct LogicalLine {
    number: usize,
    text: String,
    tokens: Vec<Token>,
}

fn logical_lines(text: &str) -> Vec<LogicalLine> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut open_quote: Option<char> = None;
    let mut escaped = false;

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        if buffer.is_empty() {
            start = number;
        } else {
            buffer.push(' ');
        }
        buffer.push_str(raw.trim());

        for c in code_of(raw) {
            if let Some(quote) = open_quote {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == quote {
                    open_quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' => open_quote = Some(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '\\' => escaped = true,
                _ => {}
            }
        }

        let opened = depth - count(code_of(raw), |c| matches!(c, '(' | '[' | '{'))
            + count(code_of(raw), |c| matches!(c, ')' | ']' | '}'));
        let continues = opened > 0 || open_quote.is_some() || raw.trim_end().ends_with('\\');
        if !continues {
            push_logical(&mut out, &mut buffer, start);
            depth = 0;
            open_quote = None;
            escaped = false;
        }
    }
    push_logical(&mut out, &mut buffer, start);
    out
}

fn code_of(line: &str) -> Vec<char> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '#' => break,
            '"' | '\'' => {
                quote = Some(c);
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn count(chars: Vec<char>, wanted: impl Fn(char) -> bool) -> i32 {
    chars.iter().filter(|c| wanted(**c)).count() as i32
}

fn push_logical(out: &mut Vec<LogicalLine>, buffer: &mut String, start: usize) {
    let text = std::mem::take(buffer);
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        buffer.clear();
        return;
    }
    out.push(LogicalLine {
        number: start,
        tokens: tokenize(&text),
        text,
    });
    buffer.clear();
}

pub fn scan(file: &str, text: &str) -> Vec<CodeAuditFinding> {
    let mut findings = Vec::new();
    for logical in logical_lines(text) {
        if let Some(finding) = sql_injection(file, &logical) {
            findings.push(finding);
        }
        if let Some(finding) = hardcoded_secret(file, &logical) {
            findings.push(finding);
        }
    }
    findings.sort_by_key(|finding| finding.line);
    findings
}

fn sql_injection(file: &str, logical: &LogicalLine) -> Option<CodeAuditFinding> {
    let call_at = find_sql_call(&logical.tokens)?;
    let expression = sql_argument_tokens(&logical.tokens, call_at);
    if expression_is_literal(&expression) {
        return None;
    }

    Some(CodeAuditFinding {
        rule_id: "python.sql-injection".to_string(),
        title: "Injeção de SQL por concatenação de entrada".to_string(),
        severity: Severity::High,
        file: file.to_string(),
        line: logical.number,
        evidence: sanitize(&logical.text),
        recommendation: "Use consulta parametrizada: \
            `cursor.execute(\"SELECT ... WHERE user = ?\", (user,))`."
            .to_string(),
        didactic: "Concatenar entrada do usuário na consulta deixa a entrada \
            reescrever a instrução. Com parâmetro posicional o banco recebe o \
            valor como dado, e a estrutura continua sendo a que foi escrita."
            .to_string(),
    })
}

fn find_sql_call(tokens: &[Token]) -> Option<usize> {
    tokens
        .windows(3)
        .position(|w| {
            w[0].is_punct('.')
                && w[1].ident().is_some_and(|name| SQL_CALLS.contains(&name))
                && w[2].is_punct('(')
        })
        .map(|at| at + 1)
}

fn sql_argument_tokens(tokens: &[Token], call_at: usize) -> Vec<Token> {
    let Some(Token::Punct('(')) = tokens.get(call_at + 1) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut depth = 1i32;
    for token in &tokens[call_at + 2..] {
        match token {
            Token::Punct('(' | '[' | '{') => depth += 1,
            Token::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Token::Punct(',') if depth == 1 => break,
            _ => {}
        }
        out.push(token.clone());
    }
    out
}

fn expression_is_literal(tokens: &[Token]) -> bool {
    match tokens {
        [Token::Str(_)] => true,
        [Token::Ident(name)] => name.ends_with("string"),
        [Token::Str(_), Token::Punct(','), rest @ ..] => rest.iter().all(|t| !t.is_punct('+')),
        _ => false,
    }
}

fn hardcoded_secret(file: &str, logical: &LogicalLine) -> Option<CodeAuditFinding> {
    let tokens = &logical.tokens;

    for at in 0..tokens.len() {
        let key = match &tokens[at] {
            Token::Str(value) => {
                let lower = value.to_ascii_lowercase();
                SECRET_KEYS
                    .iter()
                    .find(|candidate| is_key_word(&lower, candidate))
                    .copied()
            }
            Token::Ident(name) => {
                let lower = name.to_ascii_lowercase();
                SECRET_KEYS
                    .iter()
                    .find(|candidate| is_key_word(&lower, candidate))
                    .copied()
            }
            _ => None,
        };
        let Some(key) = key else {
            continue;
        };

        let Some(separator) = tokens.get(at + 1) else {
            continue;
        };
        if !separator.is_punct('=') && !separator.is_punct(':') {
            continue;
        }
        let Some(value) = tokens.get(at + 2).and_then(Token::text) else {
            continue;
        };
        if value.len() < 6 || is_placeholder(value) {
            continue;
        }

        return Some(CodeAuditFinding {
            rule_id: "python.hardcoded-credential".to_string(),
            title: format!("Credencial '{key}' escrita no código-fonte"),
            severity: Severity::High,
            file: file.to_string(),
            line: logical.number,
            evidence: sanitize(&mask_literal(&logical.tokens, value)),
            recommendation: "Leia a credencial de variável de ambiente ou de \
                arquivo fora do versionamento, e mantenha um `.env.example` sem \
                valor real."
                .to_string(),
            didactic: "Credencial no código-fonte entra no histórico do git e \
                continua válida depois da rotação, porque as versões antigas \
                permanecem lá."
                .to_string(),
        });
    }
    None
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    PLACEHOLDERS.iter().any(|marker| lower.contains(marker))
}

fn mask_literal(tokens: &[Token], secret: &str) -> String {
    let masked = match secret.chars().count() {
        0..=4 => "****".to_string(),
        _ => {
            let chars: Vec<char> = secret.chars().collect();
            format!("{}****{}", chars[0], chars[chars.len() - 1])
        }
    };
    let mut rendered = Vec::with_capacity(tokens.len());
    for token in tokens {
        rendered.push(match token {
            Token::Str(value) if value == secret => Token::Str(masked.clone()),
            other => other.clone(),
        });
    }
    render(&rendered)
}

fn render(tokens: &[Token]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Ident(name) => out.push_str(name),
            Token::Str(value) => {
                out.push('"');
                out.push_str(value);
                out.push('"');
            }
            Token::Punct(c) => out.push(*c),
        }
    }
    out
}

fn sanitize(line: &str) -> String {
    let trimmed = line.trim();
    let count = trimmed.chars().count();
    if count <= 200 {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(200).collect();
    format!("{cut}…")
}

fn is_key_word(identifier: &str, candidate: &str) -> bool {
    if candidate.len() >= 4 && matches!(candidate, "pass" | "chave" | "pwd") {
        return identifier == candidate;
    }
    let bytes = identifier.as_bytes();
    let mut from = 0usize;
    while let Some(at) = identifier[from..].find(candidate) {
        let start = from + at;
        let end = start + candidate.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
        if from >= identifier.len() {
            break;
        }
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
