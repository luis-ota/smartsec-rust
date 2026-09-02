# Especificacao do TCC

## 1. Projeto e objetivo

O SmartSec e uma ferramenta open source para automatizar testes de seguranca em fluxos DevSecOps. A ferramenta recebe um IP, dominio ou URL, orquestra scanners em ambiente isolado, interpreta os resultados com apoio de inteligencia artificial, apresenta o progresso em uma TUI e gera relatorios compreensiveis com evidencias e recomendacoes.

O objetivo geral e desenvolver uma ferramenta capaz de orquestrar analises de seguranca em ambiente isolado e interpretar seus resultados com IA agentica, reduzindo a dependencia de especialistas para equipes de engenharia de software.

O SmartSec nao substitui integralmente um especialista. Resultados devem ser rastreaveis, apresentar evidencias e deixar claras as limitacoes, incertezas e falhas de execucao.

## 2. Publico-alvo

- Engenheiro de software.
- Desenvolvedor autonomo.
- Estudante de Tecnologia da Informacao.
- Analista DevSecOps.

## 3. Escopo funcional

### Entradas

- IP, dominio ou URL de aplicacao web.
- Parametros de linha de comando.
- Arquivo de configuracao.
- Selecao de ferramentas e modelo de IA.

### Processamento

- Execucao manual ou automatica de scanners.
- Execucao em containers Podman rootless.
- Coleta e persistencia de stdout e stderr.
- Interpretacao dos logs por LLM.
- Decisao dinamica sobre testes subsequentes.
- Classificacao por severidade.
- Correlacao, deduplicacao e enriquecimento com CVE/NVD.
- Regras automaticas de interrupcao.

### Ferramentas previstas

Nmap, Nuclei, OWASP ZAP, SQLMap, Nikto e TruffleHog. O SmartSec orquestra ferramentas existentes; nao desenvolve scanners proprios.

### Modelos previstos

- GPT-4o remoto.
- Llama 3.1 8B via Ollama local.
- Claude somente se for mantido como compromisso explicito na matriz de escopo.

### Interfaces e saidas

- CLI para execucao e automacao.
- TUI para configuracao, progresso, logs e resultados.
- Modo headless para CI/CD.
- Logs estruturados e historico de execucoes.
- Relatorios Markdown e PDF.
- Exit codes padronizados.
- Recomendacoes de remediacao em linguagem acessivel.

### Plataforma

O foco principal e Linux, com Podman rootless como engine de isolamento e GitHub Actions como ambiente principal de validacao CI/CD. Docker pode ser usado apenas como contingencia documentada, nao como substituto silencioso do requisito Podman.

## 4. Requisitos funcionais

| ID | Requisito |
|---|---|
| REQ01 | Configurar alvo por IP, dominio ou URL via CLI. |
| REQ02 | Configurar ambiente, parametros e ferramentas. |
| REQ03 | Selecionar modelo de IA, incluindo GPT-4o, Claude se mantido, e Ollama. |
| REQ04 | Integrar a execucao a CI/CD em eventos como push, merge ou build. |
| REQ05 | Configurar regras de interrupcao automatica, por exemplo quantidade de achados criticos. |
| REQ06 | Executar ferramentas automaticamente e de forma orquestrada. |
| REQ07 | Executar ferramentas em containers Podman rootless. |
| REQ08 | Permitir executar manualmente ferramentas especificas sem decisao automatica. |
| REQ09 | Coletar e armazenar logs tecnicos. |
| REQ10 | Interpretar logs por IA. |
| REQ11 | Integrar CVE/NVD para validar e enriquecer achados. |
| REQ12 | Decidir dinamicamente as ferramentas seguintes. |
| REQ13 | Mostrar progresso em tempo real na TUI. |
| REQ14 | Pausar, retomar ou interromper execucoes manualmente. |
| REQ15 | Destacar vulnerabilidades criticas. |
| REQ16 | Traduzir resultados para linguagem compreensivel, com impacto e correcoes. |
| REQ17 | Gerar relatorio com vulnerabilidades, severidade, evidencias e recomendacoes. |
| REQ18 | Exportar relatorios Markdown e PDF. |
| REQ19 | Manter historico consultavel para auditoria. |

## 5. Requisitos nao funcionais

| ID | Requisito |
|---|---|
| RNF01 | Isolamento com Podman rootless. |
| RNF02 | Boa performance e baixo tempo de resposta. |
| RNF03 | Compatibilidade com Linux. |
| RNF04 | Interpretacao de logs pela IA em ate 45 segundos por ferramenta. |
| RNF05 | HTTPS e autenticacao por token nas APIs externas. |
| RNF06 | Retentativa limitada e fallback para modelo local. |
| RNF07 | TUI responsiva e legivel em terminal minimo de 80x24. |
| RNF08 | Adicionar ferramentas por configuracao sem recompilar o nucleo. |
| RNF09 | Logs persistentes, versoes e hashes das ferramentas para reproducibilidade. |
| RNF10 | Proteger dados sensiveis e obter consentimento antes de enviar logs a IA remota. |
| RNF11 | Modo headless com exit codes padronizados. |

## 6. Arquitetura esperada

```text
CLI/TUI
  -> configuracao e validacao do alvo
  -> orquestrador
       -> executor Podman rootless
       -> runners e parsers das ferramentas
       -> logs e historico
       -> agente de IA e provedores remoto/local
       -> correlacao e enriquecimento CVE/NVD
  -> resultados estruturados
       -> TUI, Markdown, PDF e CI/CD
```

Modulos atuais do prototipo:

- `src/main.rs`: entrada CLI, TUI e headless.
- `src/tui/`: telas, eventos e estado da interface.
- `src/orchestrator/`: pipeline, sandbox e parsers.
- `src/tools/`: runners reais e mocks.
- `src/ai/` e `src/llm/`: agente e provedores LLM.
- `src/domain/`: severidade, ferramentas e vulnerabilidades.
- `src/config/`: configuracao e persistencia.
- `src/report/`: geracao de relatorios.

## 7. Estado conhecido do prototipo

O prototipo possui TUI, configuracao, suporte a mouse, relatorio Markdown e integracao parcial real com Nuclei. A maioria das ferramentas ainda e mockada. O Nmap possui codigo, mas estava desconectado do catalogo/pipeline. A sandbox atual e simulada. A TUI apresenta uma animacao de IA sem chamar o agente no fluxo principal. O modo headless monta o relatorio, mas precisa garantir a gravacao real do arquivo.

Nenhum finding demonstrativo pode ser misturado a uma execucao real. Dados de demonstracao devem exigir modo explicito e ser marcados como `demo` ou `mock`.

O modo demonstrativo e ativado explicitamente com `--demo`. Cada finding deve manter campos proprietarios e proveniencia com origem, ferramenta, alvo, evidencia e timestamp; o modo real somente aceita achados produzidos pelos parsers dos scanners executados.

## 8. Macro-sprints

### Sprint 1 - Nucleo de Orquestracao e Isolamento

Prazo: 14/09/2026.

Entregar CLI, configuracao de alvo, executor Podman rootless, Nmap e Nuclei reais, logs persistentes, modelo de dados rastreavel e primeira decisao dinamica por IA remoto/local.

Issues: #2, #3, #4, #6, #7, #9, #10, #11, #12 e #13.

### Sprint 2 - Expansao, Relatorios e DevOps

Prazo: 26/10/2026.

Entregar as seis ferramentas, arquitetura extensivel, TUI ligada ao pipeline real, pausa/retomada/cancelamento, correlacao CVE/NVD, IA real na TUI e headless, historico, Markdown/PDF, exit codes e GitHub Actions. A preparacao da validacao deve comecar nesta sprint.

Issues: #14, #15, #17, #18, #19, #20, #21, #22, #23, #24, #25, #26, #27 e #28.

### Sprint 3 - Validacao Tecnica e Metricas

Prazo: 09/11/2026.

Executar validacao em DVWA 2.3 e OWASP Juice Shop 16, comparar GPT-4o e Llama 3.1, homologar CI/CD, medir eficacia e desempenho, realizar avaliacao com especialistas e publico-alvo e consolidar resultados.

Issues: #29, #30, #31, #32, #33 e #34.

## 9. Validacao e metas

### Validacao tecnica

1. Subir DVWA e Juice Shop em ambiente local isolado.
2. Registrar a matriz de vulnerabilidades conhecidas (ground truth).
3. Executar os cenarios com GPT-4o e Llama 3.1.
4. Preservar logs brutos, configuracao e relatorios.
5. Cruzar achados automatizados com o ground truth.

### Validacao DevSecOps

Executar o modo headless no GitHub Actions e comprovar os tres exit codes, os artefatos publicados e o tempo total do pipeline.

### Validacao humana

Realizar sessoes supervisionadas com especialistas e testes com estudantes/desenvolvedores generalistas. Aplicar questionario Likert de cinco pontos nas dimensoes:

- Facilidade de Uso Percebida (EU).
- Utilidade Percebida (UP).
- Intencao de Uso Futuro (IU).

O CEP nao e pre-condicao para este TCC de desenvolvimento de ferramenta, conforme orientacao registrada na reuniao. A validacao com pessoas continua obrigatoria, com consentimento, anonimizacao e tratamento responsavel dos dados.

### Metas de aceite

| Criterio | Meta |
|---|---:|
| Deteccao de vulnerabilidades conhecidas | >= 70% |
| Falsos positivos | <= 20% |
| Qualidade dos relatorios | media >= 4,0/5 |
| Participantes sem experiencia que concluem sem assistencia | >= 80% |
| Varredura completa | <= 15 minutos |
| Cenarios planejados no GitHub Actions | 100% de sucesso |
| Modelo local | execucao completa sem erros |
| Interpretacao da IA por ferramenta | <= 45 segundos |

## 10. Exit codes

- `0`: nenhuma vulnerabilidade critica encontrada.
- `1`: vulnerabilidade critica encontrada.
- `2`: erro interno, de configuracao ou de execucao.

Erro de scanner nao pode ser convertido em sucesso. Finding critico nao e erro interno: deve retornar `1` e preservar o relatorio.

## 11. Entregaveis

- Codigo da CLI, TUI e modo headless.
- Configuracao versionada e documentada.
- Orquestrador com Podman rootless.
- Integracoes com Nmap, Nuclei, ZAP, SQLMap, Nikto e TruffleHog.
- Agente LLM remoto/local e registros de decisao.
- Logs, historico e findings com proveniencia.
- Relatorios Markdown e PDF.
- Workflow GitHub Actions.
- Fixtures, testes e evidencias de validacao.
- Matriz de requisitos, metricas, limitacoes e resultados para o TCC.

## 12. Documentos de referencia

- Proposta: `docs/BES_TCC_Proposta de Desenvolvimento de Ferramenta_v2023 (final).docx`
- Plano de sprints: `docs/BES_TCC_Plano_de_Sprints_v2026_preenchido.docx`
- Reuniao de orientacao: `docs/call_8.txt`
- Distribuicao atual: `docs/PLANO_DE_DISTRIBUICAO.md`
