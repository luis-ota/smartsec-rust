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
    /// String com prefixo `f` e interpolacao: o conteudo e montado em tempo de
    /// execucao, ao contrario de `Str`.
    FStr(String),
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
            Token::Str(value) | Token::FStr(value) => Some(value),
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
            tokens.push(Token::Str(value));
            index = cursor + 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = index;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            let word: String = chars[start..index].iter().collect();
            // `f` só é prefixo de string se a aspa vier logo depois: sem esse
            // teste, um atributo como `b.x` viraria `bstring`, e um literal de
            // bytes deixaria de ser lido como constante.
            let is_string_prefix = word.chars().count() == 1
                && matches!(word.as_str(), "f" | "b" | "r" | "u" | "F" | "B" | "R" | "U")
                && matches!(chars.get(index), Some('"') | Some('\''));
            if is_string_prefix {
                // Consome a aspa e emite um literal marcado, para que a regra de
                // SQLi diferencie interpolacao de literal puro.
                let quote = chars[index];
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
                let interpolated = word.eq_ignore_ascii_case("f") && value.contains('{');
                tokens.push(if interpolated {
                    Token::FStr(value)
                } else {
                    Token::Str(value)
                });
                index = cursor + 1;
            } else {
                tokens.push(Token::Ident(word));
            }
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

/// A varredura que alimenta o pipeline: so credencial, por enquanto.
pub fn scan(file: &str, text: &str) -> Vec<CodeAuditFinding> {
    let mut findings = Vec::new();
    for logical in logical_lines(text) {
        if let Some(finding) = hardcoded_secret(file, &logical) {
            findings.push(finding);
        }
    }
    findings.sort_by_key(|finding| finding.line);
    findings
}

/// Regra desligada: a medicao em 3.105.085 linhas deu 100% de falso positivo.
///
/// Em 8.384 arquivos reais a regra produziu 73 achados e zero verdadeiro
/// positivo, porque casa o nome do metodo sem olhar o receptor: `self.execute`
/// do setuptools, `gdb.execute`, e os internos do proprio sqlite3. Falso
/// positivo em ferramenta de seguranca treina o revisor a descartar achado, e
/// torna a densidade de achados do TCC uma metrica sem significado.
///
/// A deteccao volta sobre o modulo `ast` do proprio Python, que resolve
/// receptor, binding e linha exata. Ver docs/evidence/auditoria-codigo-fp.md.
#[allow(dead_code)]
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
            Token::FStr(value) => {
                out.push_str("f\"");
                out.push_str(value);
                out.push('"');
            }
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

/// Termos que só valem como palavra inteira.
///
/// `pass` é palavra reservada do Python e nome de coluna (`SELECT user, pass
/// FROM users`); `pwd` e `chave` são curtos demais para casar por segmento sem
/// capturar `bypass` ou `chaveiro`.
const EXATOS: &[&str] = &["pass", "pwd", "chave", "senha"];

/// Sufixos que indicam que o valor **não** é a credencial em claro.
const NAO_SAO_SEGREDOS: &[&str] = &["hash", "enc", "encoded", "alg", "len", "file", "path"];

/// O identificador nomeia uma credencial?
///
/// O nome é lido por segmento: `DB_PASSWORD`, `self.db_password` e
/// `AWS_SECRET_KEY` nomeiam a mesma coisa, e exigir que o termo fosse a palavra
/// inteira ou o sufixo descartava as duas formas mais comuns em projeto Python.
fn is_key_word(identifier: &str, candidate: &str) -> bool {
    if EXATOS.contains(&candidate) {
        return identifier == candidate;
    }
    let lower = identifier.to_ascii_lowercase();
    let partes: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).collect();

    for janela in 1..=2usize {
        for at in 0..partes.len().saturating_sub(janela - 1) {
            let trecho = partes[at..at + janela].join("");
            if trecho != candidate.replace('_', "") {
                continue;
            }
            let proxima = partes.get(at + janela).copied().unwrap_or("");
            return !NAO_SAO_SEGREDOS.contains(&proxima);
        }
    }
    false
}

/// A varredura completa, incluindo a regra de injecao desligada.
#[cfg(test)]
pub fn scan_emitting_sql_injection(file: &str, text: &str) -> Vec<CodeAuditFinding> {
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
