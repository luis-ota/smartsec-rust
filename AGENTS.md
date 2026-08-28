# Regras para Agentes e Colaboradores

Estas regras valem para qualquer agente, automacao ou colaborador que altere o repositorio.

## Regra principal

Cada agente trabalha somente na issue que lhe foi atribuida. Antes de editar:

1. Ler a issue, este arquivo e `TCC_SPEC.md`.
2. Confirmar o milestone e os criterios de aceite.
3. Inspecionar o estado atual e as alteracoes da branch.
4. Identificar dependencias e contratos afetados.

Se a tarefa exigir alteracao fora do escopo, parar e registrar a necessidade na issue ou pedir autorizacao. Nao assumir tarefas de outra pessoa.

## Branches e pull requests

- Nunca fazer push direto na `main`.
- Criar uma branch por issue, preferencialmente `feat/issue-123-resumo` ou `fix/issue-123-resumo`.
- Um PR deve tratar uma issue ou um conjunto explicitamente relacionado.
- O PR deve referenciar a issue, por exemplo `Closes #123`.
- Nao misturar refatoracao, formatacao global ou mudancas de documentacao sem relacao com a issue.
- Nao reescrever ou apagar trabalho de outra branch.
- Resolver conflitos preservando a intencao das duas partes e registrar ambiguidades no PR.

## Limites de alteracao

- Nao alterar contratos publicos, formato de findings, CLI, configuracao, exit codes ou layout de logs sem atualizar `TCC_SPEC.md`, testes e a issue afetada.
- Nao remover uma ferramenta, requisito ou teste porque parece incompleto; abrir uma issue de decisao.
- Nao introduzir mock no fluxo real.
- Dados demo devem ser opt-in e identificados como `demo`/`mock`.
- Nunca usar `Box::leak` para contornar ownership de dados dinamicos.
- Nao adicionar dependencia sem justificar no PR e verificar licenca, versao e impacto.
- Nao alterar arquivos de credenciais, secrets, keyring real ou configuracoes pessoais.

## Idioma do projeto

- Escrever em portugues brasileiro todas as strings de interface, mensagens de erro, logs, textos operacionais e relatorios produzidos pelo SmartSec.
- Manter em ingles nomes de variaveis, funcoes, tipos, traits, modulos, campos, APIs e demais identificadores de codigo.
- Nao traduzir protocolos, comandos, nomes proprios nem saidas recebidas de ferramentas e servicos externos.

## Seguranca operacional

- Executar scanners somente contra alvos locais, ambientes controlados ou alvos com autorizacao explicita.
- Nunca incluir API keys, tokens, secrets ou valores detectados em commits, logs, screenshots ou relatorios.
- Mascarar secrets de TruffleHog e dados sensiveis dos prompts.
- Nao enviar logs para LLM remoto sem consentimento e sem documentar o fluxo.
- Nao aumentar concorrencia, agressividade ou permissao de scanner sem criterio de seguranca e aceite registrado.

## Qualidade obrigatoria

Todo PR deve:

- Implementar ou atualizar testes da mudanca.
- Verificar erros, timeouts, cancelamento e entradas invalidas aplicaveis.
- Executar `cargo fmt --check`, `cargo clippy -- -D warnings` e `cargo test`.
- Explicar comandos de validacao e resultado no PR.
- Atualizar documentacao e matriz de rastreabilidade quando o requisito mudar.
- Incluir evidencia reproduzivel para mudancas de TUI, CLI, pipeline ou relatorio.

Nao marcar uma issue como concluida apenas porque compila. O criterio de aceite inteiro precisa estar demonstrado.

## Responsabilidades por area

- Luis revisa arquitetura, executor, modelo de dados, IA, seguranca e contratos do pipeline.
- Passossss revisa CLI, TUI, UX, ferramentas, relatorios e fluxos de uso.
- Victor revisa testes, reproducibilidade, metricas, validacao e evidencias academicas.

Uma revisao nao transfere a responsabilidade primaria da issue. O autor continua responsavel por corrigir feedback.

## Regras para issues

- Atualizar a issue com bloqueios, decisoes e mudancas de escopo.
- Nao fechar issue com workaround temporario sem abrir follow-up.
- Se uma issue ficar grande demais, dividir antes de implementar.
- Se duas issues dependerem do mesmo contrato, combinar a interface antes de codificar.
- Issues de validacao devem preservar dados brutos e distinguir resultados antes/depois de uma correcao.

## Definition of Done

Uma issue esta pronta quando:

1. Todos os criterios de aceite foram atendidos.
2. Testes e verificacoes automatizadas passam.
3. O comportamento de erro foi considerado.
4. Documentacao e rastreabilidade foram atualizadas.
5. O PR foi revisado e aprovado.
6. A branch foi integrada por PR, nunca por push na `main`.
