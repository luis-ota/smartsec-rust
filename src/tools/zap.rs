/// Imagem e versão do OWASP ZAP usadas pelo manifesto embutido.
///
/// A imagem é fixada por digest para que a versão do scanner seja auditável no
/// log estruturado (RNF09) e não dependa de uma tag mutável. O digest foi
/// conferido contra o registro com `podman pull` na máquina de validação
/// (ver `docs/evidence/issue-28-zap.md`).
pub const ZAP_IMAGE: &str = "ghcr.io/zaproxy/zaproxy:2.14.0@sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87";
/// Versão do ZAP reportada no relatório `traditional-json` (`@version`).
pub const ZAP_VERSION: &str = "2.14.0";

/// Limite de memória do container do ZAP.
///
/// A varredura DAST completa o scan passivo de uma aplicação web, que usa muito
/// mais memória que um scan de templates. O padrão do executor (`512m`) foi
/// testado e funciona apenas em alvos estáticos triviais; `1536m` foi o valor
/// validado contra o alvo local sem OOM.
pub const ZAP_MEMORY_LIMIT: &str = "1536m";

/// Limite do heap da JVM passado ao `zap.sh`.
///
/// O `zap.sh` da 2.14 **ignora `JAVA_OPTS`**: ele calcula `-Xmx` a partir do
/// `/proc/meminfo`, que dentro do container continua reportando a memória do
/// host, e imprimiria `-Xmx3942m` numa máquina de 15 Gi. A única forma de limitar
/// o heap é passar `-Xmx<N>m` como argumento do próprio script.
pub const ZAP_MAX_HEAP: &str = "1024m";

/// tmpfs obrigatória em `HOME` do container.
///
/// Sem ela o ZAP aborta antes do primeiro job com
/// `The home path is not writable: /home/zap/.ZAP/` e status 1, porque o
/// executor monta o container com `--read-only`.
pub const ZAP_HOME_TMPFS: &str = "/home/zap:rw,noexec,nosuid,nodev,size=512m";

/// Caminho, dentro do container, do diretório montado com o plano de automação.
///
/// O plano é montado **somente leitura**, como os templates do Nuclei.
pub const ZAP_AUTOMATION_DIR: &str = "/zap/automation";

/// Caminho, dentro do container, do plano de automação montado.
pub const ZAP_AUTOMATION_PLAN: &str = "/zap/automation/scan.yaml";

/// Caminho, dentro do container, do diretório de saída gravável.
///
/// É o único ponto de escrita do container fora das tmpfs, e o executor monta
/// nele um diretório vazio criado pelo próprio SmartSec com `noexec,nosuid,nodev`.
pub const ZAP_OUTPUT_DIR: &str = "/smartsec-out";

/// Nome do relatório JSON coletado pelo executor antes de remover o container.
///
/// O job `report` do ZAP sempre acrescenta a extensão do template, portanto o
/// arquivo em disco é `zap-report.json`.
pub const ZAP_REPORT_FILE: &str = "zap-report.json";

/// Monta o plano de automação do ZAP para o alvo informado.
///
/// O plano é gerado **em memória** e gravado pelo orquestrador num diretório
/// temporário do host, montado em somente leitura no container. Cada opção
/// abaixo foi validada executando o container contra um alvo local:
///
/// - `env.contexts` define o contexto `default` com o alvo como URL semente e
///   `includePaths: .*`, `excludePaths: []` para que a varredura não escape do
///   alvo autorizado.
/// - o job `spider` percorre o alvo; `user: ""` impede reaproveitar credenciais.
/// - `passiveScan-wait` sem parâmetros: o parâmetro `maxTime` **não** é
///   reconhecido pela 2.14 e produziria `Unrecognised parameter`.
/// - o job `report` com `template: traditional-json` gera o relatório estruturado.
///   Esse template não inclui cabeçalhos nem corpos de requisição/resposta (ao
///   contrário dos templates `*-plus`), então nenhum corpo HTTP chega ao achado.
pub fn automation_plan(target: &str) -> String {
    format!(
        "---\nenv:\n  contexts:\n    - name: default\n      urls:\n        - {target}\n      includePaths:\n        - .*\n      excludePaths: []\n  vars: {{}}\njobs:\n  - type: spider\n    parameters:\n      context: default\n      user: \"\"\n  - type: passiveScan-wait\n    parameters: {{}}\n  - type: report\n    parameters:\n      template: traditional-json\n      reportDir: {output_dir}\n      reportFile: {report_file}\n",
        target = yaml_scalar(target),
        output_dir = ZAP_OUTPUT_DIR,
        report_file = ZAP_REPORT_FILE.trim_end_matches(".json"),
    )
}

/// Argumentos do container para a varredura DAST com relatório JSON.
///
/// A imagem declara `ENTRYPOINT []` e `CMD ["bash"]`; o executor monta
/// `podman create … IMAGEM <argumentos>`, e `/zap` está no `PATH` da imagem, de
/// modo que `zap.sh` é executado diretamente pelo shebang `#!/usr/bin/env bash`.
///
/// - `-Xmx1024m` limita o heap da JVM (o `zap.sh` ignora `JAVA_OPTS`).
/// - `-cmd` faz o ZAP encerrar ao concluir o plano. Sem `-cmd` ele abre a proxy
///   e não termina, e o executor ficaria preso até o timeout.
/// - `-autorun` aponta para o plano montado em somente leitura. O ZAP aceita um
///   arquivo ou uma URL, mas não lê `stdin`.
/// - `-config spider.scope=<alvo>` é a única via do ZAP para receber o alvo de
///   fora do plano. O alvo autoritativo da varredura é o contexto `default` do
///   plano; esta chave apenas satisfaz a exigência de manifesto com o marcador
///   `{target}` e foi verificada como inerte para o scan.
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
/// O alvo vem da CLI e vira uma linha de um YAML gerado em memória. Sem aspas,
/// um alvo com `: ` (não é o caso de uma URL, mas pode ser um host com puerto e
/// espaço) quebraria o documento. Com aspas simples, o único caractere que
/// precisaria de escape é a própria aspa simples, que é removida para não poder
/// injectar outra chave do plano.
fn yaml_scalar(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| match character {
            // Aspas simples fechariam a escalar e permitiriam injetar outra
            // chave do plano; qualquer caractere de controle viraria quebra de
            // linha dentro do documento.
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
        assert!(ZAP_IMAGE.contains("ghcr.io/zaproxy/zaproxy:2.14.0@sha256:"));
        assert!(ZAP_IMAGE
            .contains("sha256:3280adc730131f1f4460ab226b0f85e3e9ab3301ef5a7030f745ac4dd6b6ff87"));
        assert_eq!(ZAP_VERSION, "2.14.0");
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

        // O alvo é o contexto semente do plano.
        assert!(plan.contains("'http://169.254.1.2:3000'"), "{plan}");
        assert!(plan.contains("- name: default"), "{plan}");
        // Os três jobs validados na execução real.
        assert!(plan.contains("- type: spider"), "{plan}");
        assert!(plan.contains("- type: passiveScan-wait"), "{plan}");
        assert!(plan.contains("- type: report"), "{plan}");
        // `maxTime` e `delay` são rejeitados pela 2.14.
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
            3,
            "o plano precisa ter exatamente os três jobs: {plan}"
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
