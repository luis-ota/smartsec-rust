# Agente de código

O SmartSec não termina em "achado encontrado". Depois que os scanners classificam
e a IA interpreta os logs, uma última fase **explora a codebase do alvo** para
dizer *onde* corrigir cada achado, em `arquivo:linha`, e quais passos de correção
dar no próprio código.

Esta fase é a issue #76. Este documento descreve o fluxo, os limites e os riscos.

## Fluxo

```text
scanners (Nmap, Nuclei, Nikto, ...)
    -> build_findings            achados com severidade autoritativa
    -> analyze_findings          interpretação dos logs por IA (#23)
    -> analyze_code              FASE DO AGENTE DE CÓDIGO (#76)
         |- abre o workspace (--project, padrão: diretório atual)
         |- para cada achado, dentro de 45 s (RNF04):
         |     |- monta as pistas (ferramenta, alvo, título, evidência)
         |     |- laço de tool calling com o modelo
         |     |     |- o modelo pede uma ferramenta
         |     |     |- o registro local executa pelo sandbox read-only
         |     |     |- o resultado volta ao modelo no mesmo turno
         |     |     `- repete até a resposta ou o teto de iterações
         |     |- a localização só é aceita se a linha foi lida de fato
         |     `- senão: "localização não determinada" com o motivo
         `- grava arquivo, linha e correção em cada achado
    -> relatório Markdown + log estruturado
```

A fase roda **depois** dos scanners por um motivo específico: a severidade já
está classificada. O agente aponta onde corrigir e nunca reclassifica
(TCC_SPEC, seção 7).

## As três peças

| Módulo | Responsabilidade |
|---|---|
| `src/code_agent/workspace.rs` | Sandbox de leitura: canonicaliza, exige contenção na raiz, nunca escreve |
| `src/code_agent/tools.rs` | Registro das ferramentas locais e suas recusas acionáveis |
| `src/code_agent/agent.rs` | Laço de tool calling, verificação da localização e registro auditável |

## Ferramentas

| Ferramenta | O que faz |
|---|---|
| `list_dir` | Lista um diretório dentro do projeto, com `/` nos subdiretórios |
| `read_file` | Lê um arquivo de texto com numeração de linha, até 64 KiB |
| `search_code` | Busca textual no projeto, ignorando build, binários e arquivos grandes |
| `run_command` | **Desabilitado por padrão.** Sem shell, com allowlist explícita |

`run_command` nasce recusada porque o pipeline nunca concede allowlist. Com a
lista vazia, a recusa diz exatamente o que fazer:

```text
o programa "sh" não está na allowlist de comandos (allowlist vazia);
habilite-o explicitamente antes de executar
```

## Limites

| Limite | Valor | Por quê |
|---|---|---|
| `max_file_bytes` | 64 KiB | Impede que um arquivo enorme estoure o contexto do modelo |
| `max_search_results` | 50 | Uma busca não pode varrer o projeto inteiro |
| `max_iterations` | 12 por achado | O modelo não pode explorar indefinidamente |
| `analysis_timeout_secs` | 45 s por achado | RNF04. Um achado caro não pode atrasar a varredura inteira |
| `command_timeout_secs` | 10 s | Comando travado é interrompido com `kill_on_drop` |

O prazo por achado interrompe **aquele** laço e a fase continua nos demais. O
registro das chamadas de ferramenta acumula fora do futuro do timeout, para que um
achado que esbote o prazo não perca as ferramentas que já executaram.

## Por que o agente não inventa arquivo e linha

Uma localização só é declarada quando o modelo aponta uma linha que **o próprio
agente leu** durante o laço, pelo sandbox. O registro dessas linhas é a única
fonte de aceitação, nunca o texto do modelo.

Se o modelo responder `src/app.py:99` sem ter lido essa linha, o resultado é
honesto:

```text
o modelo apontou src/app.py:99, mas essa linha não foi lida pelo agente
durante o laço; a localização não foi aceita para não apresentar uma
suposição como observação
```

O mesmo vale quando o provedor não implementa tool calling: ele se declara
incapaz **antes** de qualquer chamada, e a fase cai no fallback determinístico
sem inventar nada.

## Consentimento remoto (RNF10)

O dado protegido nesta fase é o **código do alvo**, que é o ativo mais sensível
do cliente — mais que a saída de um scanner. O gate é o mesmo que a issue #23 já
exige para enviar logs:

```rust
if !self.agent.allows_target_data() { /* nenhum turno é aberto */ }
```

Nenhum turno é aberto quando falta consentimento — **nem um turno sem
ferramentas**, porque qualquer ida ao provedor já seria envio de dados do alvo.

## Nunca escreve no projeto

A garantia vale para o registro que o pipeline entrega, ou seja, sem allowlist de
comandos. O teste que sustenta a promessa compara o conteúdo e a lista de
arquivos do workspace antes e depois de um laço completo, com um `run_command`
que tentaria criar um arquivo.

Esse teste encontrou um fato importante: **com allowlist, `run_command` roda no
diretório raiz do workspace e consegue criar arquivo.** Por isso a garantia de
leitura pura é do registro vazio de comandos, e é isso que o pipeline entrega. Se
alguém ligar uma allowlist, a promessa de "read-only" deixa de valer e precisa
ser revista junto.

## O que aparece onde

| Onde | O que mostra |
|---|---|
| Headless `[3/4]` | Diretório analisado, `arquivo:linha`, correção por achado e o motivo quando não há origem |
| TUI — detalhe do achado | Arquivo, linha, passos numerados; ou "localização não determinada" + motivo |
| TUI — resumo | Diretório do projeto ao lado do alvo |
| TUI — configurações | Campo "Projeto analisado", validado pelo mesmo sandbox da fase |
| TUI — rastreabilidade (F2) | Linha REQ16: origem localizada, total de achados e chamadas de ferramenta |
| Relatório | Seção "Localização no código" com **todos** os achados e o diretório no cabeçalho |
| Log estruturado | `code_project_dir`, `code_located_count`, `code_tool_calls_count`, `code_tool_calls`, `code_unavailable_reason` |

O diretório do projeto é gravado mesmo com zero achados localizados, porque é ele
que distingue "a fase rodou e não achou origem" de "a fase nunca rodou".

## Segredos

`snippet` e argumentos de comando vêm do código do alvo e podem conter segredo.
A sanitização acontece em `sanitize_text` na leitura do sandbox e novamente na
persistência do log estruturado. O teste correspondente verifica o **arquivo
gravado**, não a struct em memória — testar a struct passaria mesmo com a
sanitização removida.

## Riscos conhecidos

1. **Allowlist de comandos quebra a garantia de leitura pura.** Descrito acima.
   Hoje não há caminho de configuração que conceda a allowlist; se um dia houver,
   a documentação e o teste precisam mudar junto.

2. **Provedor remoto sempre reporta suporte a tool calling.** `OpenAIProvider`
   declara `supports_tool_calling() = true` porque o endpoint Chat Completions do
   padrão OpenAI é aceito por Ollama, NVIDIA NIM e provedores `custom`. Se o
   endpoint real não aceitar ferramentas, a fase degrada com honestidade: o turno
   volta sem chamadas e o achado fica "não determinada". Não quebra, mas gasta um
   turno.

3. **Fase pode ser lenta com muitos achados.** O teto é de 45 s **por achado**.
   Uma varredura com dezenas de achados pode gastar vários minutos na fase. O
   prazo vem do RNF04 e vale por achado, como o requisito pede.

4. **A qualidade da localização depende do modelo.** A verificação garante que a
   linha foi realmente lida, não que ela é a causa do achado. A localização é
   provável, não provada — e o relatório diz "Origem no código", sem afirmar
   causalidade.

5. **Busca textual é por substring, sem parser de linguagem.** `search_code` pode
   encontrar ocorrências irrelevantes. É por isso que a aceitação exige que o
   modelo tenha lido a linha, e não que a busca a tenha encontrado.