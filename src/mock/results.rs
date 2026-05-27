#[derive(Clone, Debug)]
pub struct Vulnerability {
    pub title: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub tool: &'static str,
    pub recommendation: &'static str,
    pub didactic: &'static str,
}

impl Vulnerability {
    pub fn mock_all() -> Vec<Self> {
        vec![
            Vulnerability {
                title: "SQL Injection no formulário de login",
                severity: "CRITICAL",
                description: "O parâmetro 'username' no endpoint /login é vulnerável a SQL injection. Um atacante pode bypassar autenticação ou extrair dados do banco.",
                tool: "SQLMap",
                recommendation: "Utilize prepared statements/parameterized queries. Implemente WAF como camada adicional.",
                didactic: "SQL Injection é quando um atacante consegue inserir código SQL malicioso em campos de entrada da aplicação. Imagine que o site monta uma query como: SELECT * FROM users WHERE name = '{input}'. Se o atacante digitar ' OR 1=1 --, a query vira: SELECT * FROM users WHERE name = '' OR 1=1 --', retornando TODOS os usuários. A solução é usar 'prepared statements', que tratam o input como texto puro, nunca como código SQL executável.",
            },
            Vulnerability {
                title: "XSS refletido no campo de busca",
                severity: "HIGH",
                description: "O parâmetro 'q' no endpoint /search reflete o input do usuário sem sanitização, permitindo execução de scripts maliciosos no browser de vítimas.",
                tool: "ZAP",
                recommendation: "Sanitize e encode todo input do usuário antes de renderizar no HTML. Implemente Content-Security-Policy.",
                didactic: "XSS (Cross-Site Scripting) acontece quando a aplicação pega o que o usuário digitou e mostra na tela sem limpar. Se alguém digitar <script>roubarDados()</script> na busca e isso aparece na página, o script roda no browser de quem acessar! A proteção é simples: nunca confie no input do usuário. Sempre 'escape' (transforme < em &lt;) antes de mostrar na tela, e use CSP (Content-Security-Policy) para dizer ao browser quais scripts podem rodar.",
            },
            Vulnerability {
                title: "Headers de segurança ausentes",
                severity: "MEDIUM",
                description: "O servidor não envia headers essenciais: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security.",
                tool: "Nikto",
                recommendation: "Configure todos os headers de segurança recomendados pela OWASP no servidor web.",
                didactic: "Headers de segurança são como 'regras' que o servidor manda para o browser. Por exemplo: X-Frame-Options diz 'não deixe outros sites me colocarem num iframe' (previne clickjacking). Strict-Transport-Security diz 'só me acesse via HTTPS'. Sem esses headers, o browser permite comportamentos inseguros. É como deixar as portas de casa sem fechadura — cada header é uma fechadura a mais.",
            },
            Vulnerability {
                title: "Dependência com vulnerabilidade conhecida (lodash 4.17.15)",
                severity: "HIGH",
                description: "A dependência lodash versão 4.17.15 possui vulnerabilidade CVE-2021-23337 (command injection). Usada em 23 arquivos do projeto.",
                tool: "Snyk",
                recommendation: "Atualize lodash para versão 4.17.21 ou superior. Revise todas as dependências regularmente.",
                didactic: "Dependências são bibliotecas de terceiros que seu projeto usa. Quando uma dessas bibliotecas tem um bug de segurança, SEU projeto também fica vulnerável — mesmo que seu código seja perfeito! É como usar uma fechadura de marca: se descobrirem que aquela marca tem defeito, todas as casas com aquela fechadura estão em risco. A solução é manter tudo atualizado e usar ferramentas como Snyk/Trivy para monitorar essas vulnerabilidades.",
            },
            Vulnerability {
                title: "Porta 22 (SSH) exposta publicamente",
                severity: "MEDIUM",
                description: "O servidor SSH está acessível diretamente na internet sem restrição de IP, permitindo ataques de brute force.",
                tool: "Nmap",
                recommendation: "Restrinja acesso SSH via firewall a IPs específicos. Use autenticação por chave + desabilite password auth.",
                didactic: "Ter SSH aberto para toda a internet é como deixar a porta do servidor aberta. Robôs na internet tentam senhas comuns 24/7 (brute force). Se sua senha for fraca, invadem em minutos. Soluções: (1) Restrinja quais IPs podem conectar, (2) Use chaves criptográficas em vez de senhas, (3) Mude a porta padrão (22) para algo não-óbvio, (4) Use fail2ban para bloquear IPs que erram muitas senhas.",
            },
            Vulnerability {
                title: "Imagem Docker com usuário root",
                severity: "LOW",
                description: "O container roda como root por padrão, aumentando o impacto em caso de container escape.",
                tool: "Trivy",
                recommendation: "Crie um usuário não-root no Dockerfile e use USER directive.",
                didactic: "Quando um container Docker roda como root, se alguém conseguir 'escapar' do container, terá acesso root ao servidor inteiro. É como dirigir um carro com a chave na ignição o tempo todo — se roubarem o carro, levam tudo. Rodando como usuário comum, mesmo que invadam o container, o dano é limitado. Basta adicionar 'USER appuser' no Dockerfile para mitigar.",
            },
            Vulnerability {
                title: "Cookies sem flag HttpOnly/Secure",
                severity: "MEDIUM",
                description: "Cookies de sessão são enviados sem flags HttpOnly e Secure, permitindo roubo via XSS e transmissão em HTTP claro.",
                tool: "BurpSuite",
                recommendation: "Configure todos os cookies de sessão com flags HttpOnly, Secure e SameSite=Strict.",
                didactic: "Cookies são pequenos arquivos que o browser guarda para lembrar quem você é (sua sessão). Sem a flag 'HttpOnly', um script malicioso pode ler o cookie e roubar sua sessão. Sem 'Secure', o cookie viaja em texto puro se você acessar HTTP. Sem 'SameSite', outros sites podem enviar seu cookie (CSRF). É como uma carteira: HttpOnly = dentro do bolso (não acessível), Secure = corrente na carteira, SameSite = só abre para você.",
            },
            Vulnerability {
                title: "Path Traversal na rota /api/files",
                severity: "CRITICAL",
                description: "O endpoint /api/files?path= permite leitura de arquivos arbitrários no servidor via sequência '../' no parâmetro path.",
                tool: "ZAP",
                recommendation: "Valide e normalize todos os paths. Use chroot ou whitelist de diretórios permitidos.",
                didactic: "Path Traversal é quando o atacante consegue 'navegar' para pastas que não deveria. Se o site permite baixar arquivos com /api/files?path=documento.pdf, um atacante pode pedir /api/files?path=../../../../etc/passwd e ler arquivos do sistema! Os '../' significam 'volte uma pasta'. É como se alguém pedisse um arquivo do armário e você desse acesso ao escritório inteiro. A solução é validar que o path nunca saia do diretório permitido.",
            },
        ]
    }

    pub fn severity_color(severity: &str) -> ratatui::style::Color {
        match severity {
            "CRITICAL" => ratatui::style::Color::Magenta,
            "HIGH" => ratatui::style::Color::Red,
            "MEDIUM" => ratatui::style::Color::Yellow,
            "LOW" => ratatui::style::Color::Cyan,
            _ => ratatui::style::Color::Gray,
        }
    }
}
