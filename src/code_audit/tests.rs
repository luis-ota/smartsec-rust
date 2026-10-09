use crate::code_audit::python;
use crate::code_audit::{audit_project, CodeAuditFinding};
use crate::domain::severity::Severity;
use std::fs;

fn rule_ids(findings: &[CodeAuditFinding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

fn scan(source: &str) -> Vec<CodeAuditFinding> {
    python::scan("x.py", source)
}

#[test]
fn injecao_sql_de_linha_unica_e_detectada() {
    let found = scan("cur.execute(\"SELECT * FROM u WHERE user = '\" + user + \"'\")");
    assert_eq!(rule_ids(&found), vec!["python.sql-injection"]);
    assert_eq!(found[0].severity, Severity::High);
}

#[test]
fn injecao_sql_quebrada_em_varias_linhas_e_detectada() {
    let fonte =
        "query = (\"SELECT * FROM u WHERE user = '\"\n         + user + \"'\")\ncur.execute(query)";
    let found = scan(fonte);
    assert_eq!(rule_ids(&found), vec!["python.sql-injection"]);
    assert_eq!(
        found[0].line, 1,
        "a linha reportada é a da atribuição, onde a query é montada"
    );
}

#[test]
fn consulta_parametrizada_nao_e_achado() {
    let found = scan("cur.execute(\"SELECT * FROM u WHERE user = ?\", (user,))");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn consulta_literal_nao_e_achado() {
    assert!(scan("cur.execute(\"SELECT 1\")").is_empty());
}

#[test]
fn metodo_chamado_text_nao_dispara_a_regra_de_sql() {
    assert!(scan("botao.text(\"clique aqui\")").is_empty());
    assert!(scan("elemento.text = \"texto\"").is_empty());
}

#[test]
fn f_string_na_consulta_e_detectada() {
    let found = scan("cur.execute(f\"SELECT * FROM u WHERE user = '{user}'\")");
    assert_eq!(rule_ids(&found), vec!["python.sql-injection"]);
}

#[test]
fn format_e_detectado() {
    let found = scan("cur.execute(\"SELECT * FROM u WHERE user = '%s'\" % user)");
    assert_eq!(rule_ids(&found), vec!["python.sql-injection"]);
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
fn o_app_vulneravel_real_produz_os_dois_achados() {
    let root = std::env::temp_dir().join(format!("audit-real-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("app.py"),
        "import sqlite3\n\n\
def buscar_usuario(user):\n\
   conn = sqlite3.connect('/tmp/app.db')\n\
   cursor = conn.execute(\n\
       \"SELECT id, user, pass FROM users WHERE user = '\" + user + \"'\"\n\
   )\n\
   return cursor.fetchall()\n",
    )
    .unwrap();
    fs::write(
        root.join("db.py"),
        "DB_CONFIG = {\n    \"host\": \"10.0.0.5\",\n    \"user\": \"admin\",\n    \"password\": \"Sup3rS3nh4!\",\n}\n",
    )
    .unwrap();

    let report = audit_project(&root, 50, 200_000);
    let mut ids: Vec<&str> = rule_ids(&report.findings);
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec!["python.hardcoded-credential", "python.sql-injection"],
        "{:?}",
        report.findings
    );

    let sqli = report
        .findings
        .iter()
        .find(|f| f.rule_id == "python.sql-injection")
        .unwrap();
    assert_eq!(sqli.file, "app.py");
    assert_eq!(sqli.line, 4, "{}", sqli.evidence);
    assert!(sqli.evidence.contains("+ user"), "{}", sqli.evidence);

    let secret = report
        .findings
        .iter()
        .find(|f| f.rule_id == "python.hardcoded-credential")
        .unwrap();
    assert_eq!(secret.file, "db.py");
    assert_eq!(secret.line, 4, "{}", secret.evidence);
    assert!(
        !secret.evidence.contains("Sup3rS3nh4!"),
        "{}",
        secret.evidence
    );

    let _ = fs::remove_dir_all(root);
}
