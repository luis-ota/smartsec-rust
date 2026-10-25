/// Imagem e versão do OWASP ZAP do manifesto embutido, fixadas por digest para a
/// versão ser auditável no log estruturado (RNF09); o digest foi conferido com
/// `podman pull` contra o registro (`docs/evidence/issue-28-zap.md`).
pub const ZAP_IMAGE: &str = "ghcr.io/zaproxy/zaproxy:2.16.0@sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908";
/// Versão do ZAP reportada no relatório `traditional-json` (`@version`).
pub const ZAP_VERSION: &str = "2.16.0";

/// Limite de memória do container do ZAP: a varredura DAST usa muito mais memória
/// que um scan de templates. O padrão do executor (`512m`) só funciona em alvos
/// estáticos triviais; `1536m` foi validado contra o alvo local sem OOM.
pub const ZAP_MEMORY_LIMIT: &str = "1536m";

/// Limite do heap da JVM passado ao `zap.sh`, que **ignora `JAVA_OPTS`** e
/// calcula `-Xmx` a partir do `/proc/meminfo` do host (imprimiria `-Xmx3942m`
/// numa máquina de 15 Gi): a única via é `-Xmx<N>m` como argumento do script.
pub const ZAP_MAX_HEAP: &str = "1024m";

/// tmpfs obrigatória em `HOME` do container: sem ela o ZAP aborta antes do
/// primeiro job com `The home path is not writable: /home/zap/.ZAP/` e status 1,
/// porque o executor monta o container com `--read-only`. O tamanho de 1 GiB
/// cobre a sessão e os add-ons: com 512 MiB, uma varredura real do Juice Shop
/// encheu `/home/zap` (session ~346 MiB + addOnData ~127 MiB) e o log4j passou
/// a falhar com `No space left on device`.
pub const ZAP_HOME_TMPFS: &str = "/home/zap:rw,noexec,nosuid,nodev,size=1024m";

/// Caminho, dentro do container, do diretório montado com o plano de automação,
/// em **somente leitura** como os templates do Nuclei.
pub const ZAP_AUTOMATION_DIR: &str = "/zap/automation";

/// Caminho, dentro do container, do plano de automação montado.
pub const ZAP_AUTOMATION_PLAN: &str = "/zap/automation/scan.yaml";

/// Caminho, dentro do container, do diretório de saída gravável: o único ponto de
/// escrita fora das tmpfs, montado pelo executor com `noexec,nosuid,nodev`.
pub const ZAP_OUTPUT_DIR: &str = "/smartsec-out";

/// Nome do relatório JSON coletado pelo executor antes de remover o container: o
/// job `report` do ZAP sempre acrescenta a extensão do template, então o arquivo
/// em disco é `zap-report.json`.
pub const ZAP_REPORT_FILE: &str = "zap-report.json";

/// Monta o plano de automação do ZAP para o alvo informado.
///
/// O plano é gerado **em memória** e gravado pelo orquestrador num diretório
/// temporário do host, montado em somente leitura no container; cada opção foi
/// validada executando o container contra um alvo local:
///
/// - `env.contexts` define o contexto `default` com o alvo como URL semente e
///   `includePaths` ancorado no alvo, `excludePaths: []` para a varredura não
///   escapar do alvo autorizado.
/// - o job `spider` percorre o alvo; `user: ""` impede reaproveitar credenciais
///   e `maxDuration: 3` impede que o rastreamento de links consuma o timeout de
///   15 min em alvos grandes (o Juice Shop tem centenas de rotas).
/// - `spiderAjax` complementa o spider em SPAs (o Juice Shop é Angular) usando o
///   Firefox headless da imagem; os limites de profundidade/duração evitam que
///   ele consuma o timeout de 15 min. `activeScan` fica fora por padrão: é
///   ataque ativo e exige opt-in explícito.
/// - `passiveScan-wait` vai sem parâmetros: `maxTime` **não** é reconhecido pela
///   2.16 e produziria `Unrecognised parameter for job passiveScan-wait`.
/// - o job `report` usa `template: traditional-json`, que exclui cabeçalhos e
///   corpos de requisição/resposta (ao contrário dos templates `*-plus`), então
///   nenhum corpo HTTP chega ao achado.
pub fn automation_plan(target: &str) -> String {
    let scope = yaml_scalar(&scope_regex(target));
    format!(
        "---\nenv:\n  contexts:\n    - name: default\n      urls:\n        - {target}\n      includePaths:\n        - {scope}\n      excludePaths: []\n  vars: {{}}\njobs:\n  - type: spider\n    parameters:\n      context: default\n      user: \"\"\n      maxDuration: 3\n  - type: spiderAjax\n    parameters:\n      context: default\n      user: \"\"\n      maxDuration: 3\n      maxCrawlDepth: 5\n      numberOfBrowsers: 1\n      inScopeOnly: true\n  - type: passiveScan-wait\n    parameters: {{}}\n  - type: report\n    parameters:\n      template: traditional-json\n      reportDir: {output_dir}\n      reportFile: {report_file}\n",
        target = yaml_scalar(target),
        scope = scope,
        output_dir = ZAP_OUTPUT_DIR,
        report_file = ZAP_REPORT_FILE.trim_end_matches(".json"),
    )
}

/// Regex de escopo do contexto do ZAP.
///
/// `includePaths: .*` fazia o spider seguir links externos (Google, OWASP,
/// Microsoft) e o relatório resultante era tratado como se fosse do alvo. O
/// escopo agora ancora no alvo autorizado; os metacaracteres são escapados para
/// que `.` e `:` não virem curinga.
fn scope_regex(target: &str) -> String {
    let mut escaped = String::with_capacity(target.len() + 3);
    escaped.push('^');
    for character in target.chars() {
        if matches!(
            character,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped.push_str(".*");
    escaped
}

/// Argumentos do container para a varredura DAST com relatório JSON.
///
/// A imagem declara `ENTRYPOINT []` e `CMD ["bash"]`; `/zap` está no `PATH` da
/// imagem, então `zap.sh` é executado pelo shebang `#!/usr/bin/env bash`.
///
/// - `-Xmx1024m` limita o heap da JVM (o `zap.sh` ignora `JAVA_OPTS`).
/// - `-cmd` faz o ZAP encerrar ao concluir o plano; sem ele o ZAP abre a proxy e
///   não termina, e o executor ficaria preso até o timeout.
/// - `-autorun` aponta para o plano montado em somente leitura; o ZAP aceita
///   arquivo ou URL, mas não lê `stdin`.
/// - `-config spider.scope=<alvo>` é a única via de receber o alvo de fora do
///   plano. O alvo autoritativo é o contexto `default` do plano; esta chave só
///   satisfaz a exigência de manifesto com o marcador `{target}` e foi
///   verificada como inerte para o scan.
///
/// Cada item é um argumento literal: nenhum shell é usado.
pub fn container_arguments(target: &str) -> Vec<String> {
    vec![
        "zap.sh".to_string(),
        // Argumento único: o `zap.sh` só reconhece o heap quando `-Xmx` e o
        // valor chegam no mesmo item.
        format!("-Xmx{ZAP_MAX_HEAP}"),
        "-cmd".to_string(),
        "-autorun".to_string(),
        ZAP_AUTOMATION_PLAN.to_string(),
        "-config".to_string(),
        format!("spider.scope={target}"),
    ]
}

/// Escapa o valor do alvo para uma escalar YAML simples.
///
/// O alvo vem da CLI e vira uma linha de um YAML gerado em memória: sem aspas,
/// um alvo com `: ` (não é o caso de uma URL, mas pode ser um host com porta e
/// espaço) quebraria o documento; com aspas simples, a própria aspa é removida
/// para não permitir injetar outra chave do plano.
fn yaml_scalar(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| match character {
            // Aspas simples fechariam a escalar e permitiriam injetar outra
            // chave; caractere de controle viraria quebra de linha no documento.
            '\'' => ' ',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect();
    format!("'{cleaned}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "http://169.254.1.2:3000";

    #[test]
    fn fixa_a_imagem_por_digest_e_registra_a_versao() {
        assert!(ZAP_IMAGE.contains("ghcr.io/zaproxy/zaproxy:2.16.0@sha256:"));
        assert!(ZAP_IMAGE
            .contains("sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908"));
        assert_eq!(ZAP_VERSION, "2.16.0");
    }

    #[test]
    fn monta_o_comando_validado_no_container() {
        let arguments = container_arguments(TARGET);

        assert_eq!(
            arguments,
            [
                "zap.sh",
                "-Xmx1024m",
                "-cmd",
                "-autorun",
                "/zap/automation/scan.yaml",
                "-config",
                "spider.scope=http://169.254.1.2:3000",
            ]
        );
        // `-cmd` é obrigatório para o container encerrar.
        assert!(arguments.contains(&"-cmd".to_string()));
        // O plano vem do volume somente leitura.
        assert!(arguments.contains(&ZAP_AUTOMATION_PLAN.to_string()));
    }

    #[test]
    fn comando_nao_introduz_metacaractere_de_shell() {
        for argument in container_arguments("http://alvo.local:8080") {
            for forbidden in ['|', '>', '<', ';', '$', '&', '`', '\n'] {
                assert!(!argument.contains(forbidden), "{argument}");
            }
        }
    }

    #[test]
    fn monta_o_plano_de_automacao_com_o_alvo_e_sem_parametros_invalidos() {
        let plan = automation_plan(TARGET);

        // O alvo é o contexto semente do plano e o escopo é ancorado nele.
        assert!(plan.contains("'http://169.254.1.2:3000'"), "{plan}");
        assert!(plan.contains("- name: default"), "{plan}");
        assert!(
            plan.contains("includePaths:\n        - '^http://169\\.254\\.1\\.2:3000.*'"),
            "{plan}"
        );
        // Os jobs validados na execução real; o spider também precisa de
        // maxDuration para não consumir o timeout em alvos com muitas rotas.
        assert!(plan.contains("- type: spider"), "{plan}");
        assert!(plan.contains("- type: spiderAjax"), "{plan}");
        assert_eq!(plan.matches("maxDuration: 3").count(), 2, "{plan}");
        assert!(plan.contains("- type: passiveScan-wait"), "{plan}");
        assert!(plan.contains("- type: report"), "{plan}");
        // `maxTime` e `delay` ficam fora do plano validado no container.
        assert!(!plan.contains("maxTime"), "{plan}");
        // O relatório vai para o diretório gravável com a extensão implícita.
        assert!(plan.contains("template: traditional-json"), "{plan}");
        assert!(plan.contains("reportDir: /smartsec-out"), "{plan}");
        assert!(plan.contains("reportFile: zap-report"), "{plan}");
        assert!(!plan.contains("traditional-json-plus"), "{plan}");
    }

    #[test]
    fn o_alvo_nao_injeta_outra_chave_do_plano() {
        let plan = automation_plan("http://alvo.local\njobs:\n  - type: report\n");

        // O alvo injetado fica confinado a uma escalar de uma linha.
        assert!(
            plan.contains("- 'http://alvo.local jobs:   - type: report '"),
            "{plan}"
        );
        assert_eq!(
            plan.lines()
                .filter(|line| line.trim_start().starts_with("- type:"))
                .count(),
            4,
            "o plano precisa ter exatamente os quatro jobs: {plan}"
        );
    }

    #[test]
    fn exige_tmpfs_em_home_e_rewrite_de_saida() {
        // Sem tmpfs em /home/zap o ZAP aborta com "home path is not writable".
        assert!(ZAP_HOME_TMPFS.starts_with("/home/zap:rw,"));
        assert!(ZAP_HOME_TMPFS.contains("noexec"));
        assert!(ZAP_OUTPUT_DIR.starts_with('/'));
        assert_eq!(ZAP_REPORT_FILE, "zap-report.json");
    }
}
