/// Achados simulados para o modo demo (`--demo`).
///
/// **Nunca** devem ser incluídos em uma execução real.
/// Todos os achados aqui têm `source: FindingSource::Demo`.
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::domain::Severity;

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    // Aproximação de data para modo demo (sem dependência de chrono).
    format!("2026-01-01T{:02}:{:02}:{:02}Z", h, m, s)
}

/// Retorna todos os achados de demonstração.
///
/// Só deve ser chamada quando `config.demo_mode == true`.
pub fn demo_all(target: &str) -> Vec<Vulnerability> {
    let ts = now_iso8601();
    let t = target.to_string();

    vec![
        Vulnerability {
            title: "SQL Injection no formulário de login".to_string(),
            severity: Severity::Critical,
            description: "O parâmetro 'username' no endpoint /login é vulnerável a SQL injection. Um atacante pode bypassar autenticação ou extrair dados do banco.".to_string(),
            tool: "SQLMap".to_string(),
            recommendation: "Utilize prepared statements/parameterized queries. Implemente WAF como camada adicional.".to_string(),
            didactic: "SQL Injection é quando um atacante consegue injetar código SQL malicioso em campos de entrada da aplicação.\n\nComo funciona: A aplicação monta queries como:\n SELECT * FROM users WHERE username = '{input}'\n\nSe o atacante digitar: ' OR '1'='1' --\nA query vira:\n SELECT * FROM users WHERE username = '' OR '1'='1' --'\n\nIsso retorna TODOS os usuários porque '1=1' sempre é verdadeiro. O '--' comenta o resto da query.\n\nPior: um atacante pode usar UNION para extrair dados de outras tabelas:\n ' UNION SELECT table_name FROM all_tables --\n\nImpacto: Bypass total de autenticação, roubo de dados, alteração ou exclusão de registros.\n\nPrevenção:\n 1. Prepared statements (parâmetros separados do código SQL)\n 2. Validação de input (whitelist de caracteres permitidos)\n 3. Principle of least privilege (usuário do banco com permissões mínimas)\n 4. WAF como camada adicional (nunca como única defesa)".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] sqlmap -u http://target/login --data 'username=*&password=test' → vulnerable".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "SQL Injection no parâmetro de busca".to_string(),
            severity: Severity::Critical,
            description: "O parâmetro 'q' na rota /api/search concatena diretamente ao SQL, permitindo extração de dados sensíveis como credenciais e dados de pagamento.".to_string(),
            tool: "SQLMap".to_string(),
            recommendation: "Refatore para usar ORM com parâmetros ou prepared statements. Nunca concatene input direto ao SQL.".to_string(),
            didactic: "Esta é uma variação do SQL Injection, mas num contexto diferente — uma API REST.\n\nMuitas APIs montam queries dinâmicas:\n SELECT * FROM products WHERE name LIKE '%{q}%'\n\nO atacante pode usar techniques avançadas:\n - Time-based blind: ' AND SLEEP(5) -- (se demorar 5s, existe injeção)\n - Boolean blind: ' AND 1=1 -- vs ' AND 1=2 -- (respostas diferentes)\n - Out-of-band: usar DNS ou HTTP requests para exfiltrar dados\n\nPrevenção:\n 1. ORM (Sequelize, Diesel, SQLAlchemy) já trata isso\n 2. Nunca monte SQL com string formatting\n 3. Use bibliotecas de query builder que parametrizam automaticamente\n 4. Implemente monitoring para detectar queries anormais".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] sqlmap -u http://target/api/search?q=* → time-based blind SQLi confirmed".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "XSS refletido no campo de busca".to_string(),
            severity: Severity::High,
            description: "O parâmetro 'q' no endpoint /search reflete o input do usuário sem sanitização, permitindo execução de scripts maliciosos no browser de vítimas.".to_string(),
            tool: "ZAP".to_string(),
            recommendation: "Sanitize e encode todo input do usuário antes de renderizar no HTML. Implemente Content-Security-Policy.".to_string(),
            didactic: "XSS (Cross-Site Scripting) existem em 3 variantes:\n\n1. Refletido: O script vem na URL e é mostrado na página.\n Ex: https://site.com/search?q=<script>roubarCookies()</script>\n Quando alguém clica nesse link, o script roda.\n\n2. Armazenado: O script fica salvo no banco e afeta TODOS que visitam.\n\n3. DOM-based: O JavaScript do próprio site manipula o DOM de forma insegura.\n\nPrevenção:\n 1. Escape HTML\n 2. Content-Security-Policy\n 3. HttpOnly em cookies\n 4. Nunca use innerHTML com dados do usuário".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] ZAP active scan: GET /search?q=<script>alert(1)</script> → reflected in response".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "XSS armazenado nos comentários do blog".to_string(),
            severity: Severity::High,
            description: "O campo de comentário aceita HTML/JavaScript sem sanitização. Scripts são armazenados e executados para todos os leitores do post.".to_string(),
            tool: "ZAP".to_string(),
            recommendation: "Implemente sanitização server-side com DOMPurify ou similar. Use CSP para mitigar o impacto.".to_string(),
            didactic: "XSS armazenado é mais perigoso que o refletido porque:\n\n- Afeta TODOS os visitantes, não apenas quem clica num link malicioso\n- O atacante não precisa de engenharia social — basta comentar\n- Pode propagar worm-like\n\nFluxo de ataque:\n 1. Atacante posta comentário com script malicioso\n 2. Visitante carrega a página\n 3. Script executa e exfiltra cookies\n\nDefesa em profundidade:\n 1. Sanitize input\n 2. Encode output\n 3. CSP\n 4. HttpOnly cookies".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] ZAP: POST /comments body=<img src=x onerror=alert(1)> → stored, triggered on GET /posts/1".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Headers de segurança ausentes".to_string(),
            severity: Severity::Medium,
            description: "O servidor não envia headers essenciais: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security.".to_string(),
            tool: "Nikto".to_string(),
            recommendation: "Configure todos os headers de segurança recomendados pela OWASP no servidor web.".to_string(),
            didactic: "Headers de segurança são instruções que o servidor envia para o browser. Cada um protege contra uma classe diferente de ataque:\n\n1. X-Frame-Options: DENY — previne clickjacking\n2. Strict-Transport-Security — força HTTPS\n3. X-Content-Type-Options: nosniff\n4. Content-Security-Policy — previne XSS\n5. Referrer-Policy\n6. Permissions-Policy".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] Nikto: Missing headers: X-Frame-Options, Strict-Transport-Security, Content-Security-Policy".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Dependência com vulnerabilidade conhecida (lodash 4.17.15)".to_string(),
            severity: Severity::High,
            description: "A dependência lodash versão 4.17.15 possui vulnerabilidade CVE-2021-23337 (command injection). Usada em 23 arquivos do projeto.".to_string(),
            tool: "Snyk".to_string(),
            recommendation: "Atualize lodash para versão 4.17.21 ou superior. Revise todas as dependências regularmente.".to_string(),
            didactic: "Dependências são bibliotecas de terceiros que seu projeto importa. A maioria dos projetos modernos tem 200-500 dependências transitivas.\n\nO problema: Se uma dependência tem vulnerabilidade, SEU projeto também fica afetado.\n\nPrevenção:\n 1. npm audit / cargo audit\n 2. Dependabot/Renovate\n 3. Lock files\n 4. Snyk/Trivy/Semgrep".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] Snyk: lodash@4.17.15 → CVE-2021-23337 (HIGH, CVSS 7.2)".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Dependência obsoleta com CVE de severidade crítica".to_string(),
            severity: Severity::Critical,
            description: "O pacote openssl-sys 0.9.72 contém múltiplas CVEs incluindo CVE-2023-0286 (buffer overflow). 14 dependências afetadas.".to_string(),
            tool: "Trivy".to_string(),
            recommendation: "Atualize openssl-sys para 0.9.80+. Execute 'cargo update' e verifique compatibilidade.".to_string(),
            didactic: "OpenSSL é uma biblioteca criptográfica usada por praticamente toda aplicação que usa HTTPS.\n\nCVE-2023-0286: Um atacante pode enviar dados específicos que causam memory corruption no parsing de certificados X.509.\n\nSempre atualize dependências críticas de segurança. Use 'cargo audit' regularmente.".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] Trivy: openssl-sys@0.9.72 → CVE-2023-0286 (CRITICAL, CVSS 9.1)".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Porta 22 (SSH) exposta publicamente".to_string(),
            severity: Severity::Medium,
            description: "O servidor SSH está acessível diretamente na internet sem restrição de IP, permitindo ataques de brute force.".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Restrinja acesso SSH via firewall a IPs específicos. Use autenticação por chave + desabilite password auth.".to_string(),
            didactic: "SSH (Secure Shell) é o 'controle remoto' do servidor. Se está aberto na internet, qualquer pessoa pode tentar conectar.\n\nDefesa em camadas:\n 1. Firewall: bloqueie porta 22 para IPs externos\n 2. Chaves SSH\n 3. Porta não-padrão\n 4. fail2ban\n 5. Two-factor".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] Nmap: 22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.6".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Imagem Docker com usuário root".to_string(),
            severity: Severity::Low,
            description: "O container roda como root por padrão, aumentando o impacto em caso de container escape.".to_string(),
            tool: "Trivy".to_string(),
            recommendation: "Crie um usuário não-root no Dockerfile e use USER directive.".to_string(),
            didactic: "Docker containers compartilham o kernel do host. Se um container roda como root e alguém consegue 'escape', terá root no host.\n\nNo Dockerfile:\n RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n USER appuser".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] Trivy: Container running as root (UID 0). No USER directive in Dockerfile.".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Cookies sem flag HttpOnly/Secure".to_string(),
            severity: Severity::Medium,
            description: "Cookies de sessão são enviados sem flags HttpOnly e Secure, permitindo roubo via XSS e transmissão em HTTP claro.".to_string(),
            tool: "BurpSuite".to_string(),
            recommendation: "Configure todos os cookies de sessão com flags HttpOnly, Secure e SameSite=Strict.".to_string(),
            didactic: "Cookies são como 'pulseiras de entrada'. As 3 flags essenciais:\n\n1. HttpOnly: Impede JavaScript de acessar o cookie\n2. Secure: Só envia o cookie via HTTPS\n3. SameSite: Controla envio em requests cross-site\n\nExemplo seguro:\n Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] BurpSuite: Set-Cookie: session=abc123 (missing HttpOnly, Secure, SameSite)".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Path Traversal na rota /api/files".to_string(),
            severity: Severity::Critical,
            description: "O endpoint /api/files?path= permite leitura de arquivos arbitrários no servidor via sequência '../' no parâmetro path.".to_string(),
            tool: "ZAP".to_string(),
            recommendation: "Valide e normalize todos os paths. Use chroot ou whitelist de diretórios permitidos.".to_string(),
            didactic: "Path Traversal permite navegar para fora do diretório pretendido.\n\nComo funciona:\n - App permite: /api/files?path=documento.pdf\n - Atacante tenta: /api/files?path=../../../etc/passwd\n\nPrevenção:\n 1. Normalize o path\n 2. Whitelist de diretórios\n 3. Chroot\n 4. Valide a extensão do arquivo".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] ZAP: GET /api/files?path=../../etc/passwd → 200 OK, root:x:0:0:root:/root:/bin/bash".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Insecure Direct Object Reference (IDOR)".to_string(),
            severity: Severity::High,
            description: "O endpoint /api/users/{id} retorna dados de qualquer usuário sem verificar autorização. Sequencial IDs facilitam enumeração.".to_string(),
            tool: "BurpSuite".to_string(),
            recommendation: "Implemente verificação de autorização: o usuário autenticado só deve acessar seus próprios dados.".to_string(),
            didactic: "IDOR é quando a aplicação usa IDs diretos e previsíveis para acessar recursos, SEM verificar se o usuário tem permissão.\n\nComo funciona:\n 1. Atacante loga e vê seu ID: /api/users/4521\n 2. Muda para: /api/users/4522, 4523...\n\nPrevenção:\n 1. Verifique ownership\n 2. Use UUIDs\n 3. Authorization middleware".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] BurpSuite: GET /api/users/1002 → 200 OK with PII (authenticated as user 1001)".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Cross-Site Request Forgery (CSRF) no formulário de transferência".to_string(),
            severity: Severity::High,
            description: "A rota /api/transfer não valida token CSRF. Um site malicioso pode iniciar transferências em nome do usuário autenticado.".to_string(),
            tool: "ZAP".to_string(),
            recommendation: "Implemente tokens CSRF em todos os formulários. Use SameSite=Strict nos cookies de sessão.".to_string(),
            didactic: "CSRF é quando um site malicioso faz o browser da vítima enviar requests para outro site onde ela está logada.\n\nDefesas:\n 1. CSRF Token no formulário\n 2. SameSite=Strict no cookie de sessão\n 3. Verificação de Origin/Referer header".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] ZAP: POST /api/transfer without CSRF token → 200 OK (transfer processed)".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "Server-Side Request Forgery (SSRF) no endpoint de preview".to_string(),
            severity: Severity::Critical,
            description: "O endpoint /api/preview?url= faz request para qualquer URL fornecida, permitindo acesso a serviços internos e metadados cloud.".to_string(),
            tool: "ZAP".to_string(),
            recommendation: "Whitelist de domínios permitidos. Bloqueie IPs privados/loopback. Use network segmentation.".to_string(),
            didactic: "SSRF é quando o atacante consegue que o SERVIDOR faça requests para endereços que não deveria acessar.\n\nExemplo:\n GET /api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\nPrevenção:\n 1. Whitelist de domínios\n 2. Bloqueie IPs privados\n 3. Desative protocols perigosos\n 4. Network segmentation".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] ZAP: GET /api/preview?url=http://169.254.169.254/latest/meta-data/ → AWS metadata exposed".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "CORS configurado com wildcard (*)".to_string(),
            severity: Severity::Medium,
            description: "O servidor aceita requests de qualquer origem com credenciais, permitindo que sites maliciosos acessem endpoints autenticados.".to_string(),
            tool: "BurpSuite".to_string(),
            recommendation: "Restrinja origins permitidas. Nunca use Access-Control-Allow-Origin: * com credenciais.".to_string(),
            didactic: "CORS controla quais sites podem acessar sua API.\n\nConfiguração perigosa:\n Access-Control-Allow-Origin: *\n Access-Control-Allow-Credentials: true\n\nConfiguração correta:\n Access-Control-Allow-Origin: https://meusite.com\n Access-Control-Allow-Credentials: true".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] BurpSuite: Response header Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true".to_string(),
            detected_at: ts.clone(),
        },
        Vulnerability {
            title: "JWT com algoritmo 'none' aceito".to_string(),
            severity: Severity::Critical,
            description: "A API aceita tokens JWT com algoritmo 'none', permitindo forjar tokens de admin sem chave secreta.".to_string(),
            tool: "BurpSuite".to_string(),
            recommendation: "Force algoritmo HS256/RS256. Nunca aceite 'none'. Valide issuer e audience.".to_string(),
            didactic: "JWT tem 3 partes: header.payload.signature.\n\nO ataque 'algorithm none':\n 1. Header diz qual algoritmo usar: {\"alg\": \"HS256\"}\n 2. Atacante muda para: {\"alg\": \"none\"}\n 3. Remove a assinatura completamente\n 4. Se o servidor aceita 'none' = token forjado funciona!\n\nPrevenção:\n 1. Whitelist de algoritmos: só HS256 ou RS256\n 2. Nunca confie no header do token\n 3. Use libraries maduras".to_string(),
            source: FindingSource::Demo,
            target: t.clone(),
            evidence: "[DEMO] BurpSuite: JWT with alg=none accepted → admin access granted without signature".to_string(),
            detected_at: ts.clone(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_all_findings_are_marked_as_demo() {
        let findings = demo_all("http://test.local");
        assert!(!findings.is_empty(), "demo_all deve retornar achados");
        for f in &findings {
            assert_eq!(
                f.source,
                FindingSource::Demo,
                "Achado '{}' deve ter source=Demo",
                f.title
            );
        }
    }

    #[test]
    fn demo_all_findings_have_target() {
        let target = "http://test.local";
        let findings = demo_all(target);
        for f in &findings {
            assert_eq!(
                f.target, target,
                "Achado '{}' deve ter o alvo correto",
                f.title
            );
        }
    }

    #[test]
    fn demo_all_findings_have_evidence() {
        let findings = demo_all("http://test.local");
        for f in &findings {
            assert!(
                !f.evidence.is_empty(),
                "Achado '{}' deve ter evidência",
                f.title
            );
        }
    }
}
