# Estendendo as ferramentas do SmartSec

Este documento descreve o contrato de manifesto, os runners e parsers
registrados e o procedimento para adicionar uma ferramenta sem recompilar o
núcleo (RNF08).

## Visão geral

O núcleo do SmartSec não compara nomes de ferramentas com strings mágicas. Cada
ferramenta é descrita por um `ToolManifest` e registrada no `ToolRegistry`,
que resolve:

- o **runner**: como o manifesto vira um comando executado no Podman rootless;
- o **parser**: como a saída do runner vira achados estruturados.

O catálogo é montado com as ferramentas embutidas (Nmap e Nuclei) mais as
ferramentas declaradas na chave `[[tools]]` do arquivo de configuração TOML.
Ferramentas desabilitadas (`enabled = false`) são validadas, mas ficam fora do
catálogo exibido na CLI/TUI.

## Contrato do manifesto

Todos os campos são obrigatórios, exceto `enabled` (padrão `true`).

| Campo | Tipo | Descrição |
|---|---|---|
| `name` | string | Nome exibido e chave de seleção (`--tools`, TUI). Único no catálogo (comparação sem diferenciar maiúsculas). |
| `description` | string | Texto curto exibido na TUI. |
| `category` | string | Categoria livre (ex.: `RECON`, `DAST`). |
| `image` | string | Imagem do container Podman rootless, de preferência com versão fixada. |
| `version` | string | Versão da ferramenta, gravada no log estruturado (RNF09). |
| `runner` | string | Runner registrado que executa a ferramenta. |
| `parser` | string | Parser registrado que interpreta a saída. |
| `command_template` | lista de strings | Comando do container; deve conter o marcador `{target}` em ao menos um argumento. |
| `output_format` | string | Formato esperado da saída (ex.: `text`, `xml`, `jsonl`). |
| `enabled` | bool | Opcional. `false` mantém a ferramenta fora do catálogo. |

O alvo informado na CLI substitui exatamente o marcador `{target}`. Nenhum
shell é usado: cada item da lista vira um argumento literal do container.

## Runners registrados

| Runner | Comportamento |
|---|---|
| `nmap` | Execução real do Nmap com `-Pn -sT -sV -oX -`; comportamento e argumentos definidos pelo runner. |
| `nuclei` | Execução real do Nuclei com o plano validado pelo orquestrador e templates montados em somente leitura. |
| `generic` | Executa o `command_template` do manifesto no executor Podman rootless, sem privilégios e com rede `pasta`. |

## Parsers registrados

| Parser | Comportamento |
|---|---|
| `nmap-xml` | Converte o XML do Nmap em achados rastreáveis. |
| `nuclei-jsonl` | Converte o JSONL do Nuclei em achados rastreáveis. |
| `generic-text` | Extrai achados informativos simples do texto, um por linha não vazia e não diagnóstica. |

## Procedimento para registrar uma ferramenta por configuração

1. Escolha uma imagem de container que execute a ferramenta e fixe a versão.
2. Monte o comando completo (binário + argumentos) e use `{target}` no lugar
   do alvo. Use `runner = "generic"` e `parser = "generic-text"`.
3. Adicione o bloco `[[tools]]` ao arquivo TOML usado com `--config`.
4. Valide com uma execução controlada:

   ```bash
   smartsec tool Nikto --target 169.254.1.2:3000 --config ./smartsec.toml
   ```

5. Confirme no log estruturado e no relatório que a ferramenta, a imagem e a
   versão aparecem corretamente e que os achados têm proveniência `real`.

Exemplo mínimo:

```toml
target_url = "http://169.254.1.2:3000"

[llm]
provider = "Ollama"

[[tools]]
name = "Nikto"
description = "Scanner de servidores web"
category = "DAST"
image = "docker.io/sullo/nikto:2.5.0"
version = "2.5.0"
runner = "generic"
parser = "generic-text"
command_template = ["nikto", "-host", "{target}"]
output_format = "text"
enabled = true
```

## Erros de configuração

A configuração é validada no carregamento e interrompe o fluxo com mensagem
acionável em pt-BR. Exemplos:

- ferramenta duplicada (mesmo nome de uma embutida ou de outra `[[tools]]`);
- campo obrigatório ausente: `a ferramenta 'Nikto' não define o campo obrigatório 'version' em [[tools]]`;
- runner desconhecido: `a ferramenta 'Nikto' usa o runner desconhecido 'foo'; runners registrados: nmap, nuclei, generic`;
- parser desconhecido, com a lista de parsers registrados;
- `command_template` sem o marcador `{target}`.

## Adicionando um novo runner ou parser

Registrar uma ferramenta por configuração não exige recompilar, mas ela só pode
usar runners e parsers já registrados. Para criar um runner ou parser novo:

1. Implemente a execução no executor Podman rootless existente, sem comandos
   no host e sem mock no fluxo real.
2. Registre o identificador no `ToolRegistry` (`src/tools/registry.rs`) com o
   `RunnerKind`/`ParserKind` correspondente.
3. Ligue o parser ao pipeline em `Orchestrator::build_findings`.
4. Adicione testes cobrindo argumentos, falhas, timeout e parsing.
5. Atualize este documento, o `TCC_SPEC.md` e a matriz de rastreabilidade.

Limites de segurança: nenhuma ferramenta nova deve receber privilégios extras,
montar o socket do Podman, escrever fora do tmpfs ou ser executada fora do
container. Segredos nunca entram no manifesto nem no `command_template`.
