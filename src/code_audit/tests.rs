use crate::code_audit::python;
use crate::code_audit::{audit_project, CodeAuditFinding};
use std::fs;

fn rule_ids(findings: &[CodeAuditFinding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

fn scan(source: &str) -> Vec<CodeAuditFinding> {
    python::scan("x.py", source)
}

fn sqli(source: &str) -> Vec<CodeAuditFinding> {
    python::scan_emitting_sql_injection("x.py", source)
}

#[test]
fn a_regra_de_injecao_aind_detecta_a_concatenacao_mesmo_desligada() {
    let achados = sqli("cur.execute(\"SELECT * FROM u WHERE u = '\" + x + \"'\")");
    assert_eq!(
        rule_ids(&achados),
        vec!["python.sql-injection"],
        "{achados:?}"
    );
}

#[test]
fn credencial_em_cada_forma_comum_e_detectada() {
    for fonte in [
        "senha = \"Sup3rS3nh4!\"",
        "CFG = {\"password\": \"Sup3rS3nh4!\"}",
        "self.password = \"Sup3rS3nh4!\"",
        "connect(password=\"Sup3rS3nh4!\")",
        "api_key = \"sk-live-abc123xyz\"",
        "senha = \"Sup3rS3nh4!\"  # comentario",
    ] {
        let found = scan(fonte);
        assert_eq!(
            rule_ids(&found),
            vec!["python.hardcoded-credential"],
            "não detectou: {fonte}"
        );
    }
}

#[test]
fn credencial_que_depende_de_ambiente_nao_e_achado() {
    for fonte in [
        "senha = os.getenv(\"SENHA\")",
        "password = os.environ[\"PW\"]",
        "api_key = \"changeme\"",
        "token = \"your-token-here\"",
        "password = \"xxxxxxx\"",
        "senha = \"\"",
    ] {
        assert!(scan(fonte).is_empty(), "falso positivo em: {fonte}");
    }
}

#[test]
fn a_evidencia_da_credencial_nao_repoe_o_segredo() {
    let segredo = "Sup3rS3nh4!";
    let found = scan(&format!("senha = \"{segredo}\""));
    let evidencia = found[0].evidence.clone();
    assert!(
        !evidencia.contains(segredo),
        "a evidência vazou: {evidencia}"
    );
    assert!(evidencia.contains("****"), "{evidencia}");
}

#[test]
fn credencial_multibyte_nao_entra_em_panic() {
    for segredo in ["aébcdé", "ábcdef", "senhãçãó", "日本語のパスワード"] {
        let fonte = format!("senha = \"{segredo}\"");
        let found = scan(&fonte);
        assert_eq!(rule_ids(&found), vec!["python.hardcoded-credential"]);
        assert!(!found[0].evidence.contains(segredo));
    }
}

#[test]
fn comentario_nao_vira_achado() {
    assert!(scan("# execute(\"SELECT\" + x)").is_empty());
    assert!(scan("# password = \"Sup3rS3nh4!\"").is_empty());
}

#[test]
fn a_varredura_ignora_diretorios_de_build() {
    let root = std::env::temp_dir().join(format!("audit-ignore-{}", std::process::id()));
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::create_dir_all(root.join("app")).unwrap();
    fs::write(
        root.join("node_modules/pkg/leak.py"),
        "senha = \"NodeModules123!\"\n",
    )
    .unwrap();
    fs::write(root.join("app/real.py"), "senha = \"Aplicacao12345!\"\n").unwrap();

    let report = audit_project(&root, 50, 200_000);

    let arquivos: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(arquivos, vec!["app/real.py"], "{:?}", report.findings);
    assert_eq!(report.files_scanned, 1);
    assert!(report.limitation.is_none(), "{:?}", report.limitation);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_varredura_declara_o_que_nao_conseguiu_cobrir() {
    let root = std::env::temp_dir().join(format!("audit-limite-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for index in 0..5 {
        fs::write(root.join(format!("m{index}.py")), "x = 1\n").unwrap();
    }

    let report = audit_project(&root, 2, 200_000);

    assert_eq!(report.files_scanned, 2);
    assert!(
        report
            .limitation
            .as_deref()
            .is_some_and(|t| t.contains("2 arquivos")),
        "{:?}",
        report.limitation
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn projeto_ilegivel_vira_limitacao_e_nao_panic() {
    let report = audit_project(std::path::Path::new("/nao/existe/projeto"), 10, 1000);
    assert!(report.findings.is_empty());
    assert!(report.limitation.is_some());
}
#[test]
fn o_app_vulneravel_real_produz_o_achado_de_credencial() {
    let root = std::env::temp_dir().join(format!("audit-real-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("app.py"),
        "import sqlite3\n\n\
def buscar_usuario(user):\n\
   conn = sqlite3.connect('/tmp/app.db')\n\
   cursor = conn.execute(\n\
       \"SELECT id, user, pass FROM users WHERE user = '\" + user + \"'\"\n\
   )\n",
    )
    .unwrap();
    fs::write(
        root.join("db.py"),
        "DB_CONFIG = {\n    \"host\": \"10.0.0.5\",\n    \"password\": \"Sup3rS3nh4!\",\n}\n",
    )
    .unwrap();

    let report = audit_project(&root, 50, 200_000);

    assert_eq!(
        rule_ids(&report.findings),
        vec!["python.hardcoded-credential"],
        "{:?}",
        report.findings
    );
    let secret = &report.findings[0];
    assert_eq!(secret.file, "db.py");
    assert_eq!(secret.line, 3, "{}", secret.evidence);
    assert!(
        !secret.evidence.contains("Sup3rS3nh4!"),
        "{}",
        secret.evidence
    );

    let _ = fs::remove_dir_all(root);
}

/// Formas que a revisão mediu como quebradas: prefixo em SCREAMING_SNAKE_CASE,
/// literal de bytes e o parêntese de `pass` como coluna de consulta.
#[test]
fn a_regra_de_credencial_acha_o_nome_prefixado() {
    for fonte in [
        "DB_PASSWORD = \"Sup3rS3nh4!\"",
        "MYSQL_PASSWORD = \"xYz987Ab12\"",
        "APP_SECRET = \"qwerty123456\"",
        "self.db_password = \"Sup3rS3nh4!\"",
        "AWS_SECRET_KEY = \"AKIA-exemplo-1234\"",
    ] {
        assert_eq!(
            rule_ids(&scan(fonte)),
            vec!["python.hardcoded-credential"],
            "não detectou: {fonte}"
        );
    }
}

#[test]
fn a_regra_de_credencial_nao_come_o_comeco_da_palavra() {
    for fonte in [
        "bypass = \"xYz987Ab12\"",
        "chaveiro = \"abc123def456\"",
        "tokenizer = \"modelo-vocab-2024\"",
        "password_hash = \"sha256:abc123\"",
        "cur.execute(\"SELECT user, pass FROM users\")",
    ] {
        assert!(scan(fonte).is_empty(), "falso positivo em: {fonte}");
    }
}

#[test]
fn atributo_que_comeca_coma_letra_de_prefixo_nao_vira_string() {
    assert!(scan("b.x = \"SELECT 1\"").is_empty());
    assert!(scan("f.resultado = \"texto\"").is_empty());
}

/// A regra de injecao existe mas nao e emitida: a medicao em 3.105.085 linhas
/// deu 100% de falso positivo. Emitir um achado em 73 de 73 casos errados
/// treina o revisor a ignorar a ferramenta.
#[test]
fn a_regra_de_injecao_nao_e_emitida_ate_a_auditoria_usar_o_parser_do_python() {
    let fonte = "cur.execute(\"SELECT * FROM u WHERE u = '\" + x + \"'\")";
    assert!(
        scan(fonte).is_empty(),
        "a regra de injecao ainda esta no caminho de emissao: {:?}",
        scan(fonte)
    );
}

#[test]
fn a_regra_de_credencial_continua_emitindo() {
    assert_eq!(
        rule_ids(&scan("DB_PASSWORD = \"Sup3rS3nh4!\"")),
        vec!["python.hardcoded-credential"]
    );
}
