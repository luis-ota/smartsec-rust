# Prompt de continuação — smartsec-rust + CyberRAG

> **Obsoleto.** Descreve a branch antiga `feat/auditoria-codigo-ia`, já mergeada.
> O documento de passagem atual é [`docs/HANDOFF.md`](HANDOFF.md).

Você está continuando o trabalho num repositório já avançado. **Leia tudo antes de editar qualquer coisa.**

---

## 1. Onde você está

```bash
cd ~/dev/tcc/smartsec-rust     # branch feat/auditoria-codigo-ia
git log --oneline -1           # d920d5e
git pull                       # se houver trabalho novo
```

`docs/HANDOFF.md` na raiz tem o estado detalhado. Leia.

Ambiente já pronto e validado: `cargo 1.97.1`, `podman 6.1.3`, `secret-tool`, chave da NVIDIA NIM no keyring, alvo de teste em `~/dev/app-vuln` (porta 3001, IP `192.168.1.58`), TOMLs em `/tmp/ss-nim.toml` e `/tmp/ss-sem-ia.toml`. **640 testes unitários verdes, clippy e fmt limpos.**

**Não peça chave de API a ninguém sem necessidade** — a da NIM já está no keyring. Se precisar de Groq ou OpenRouter, pergunte.

---

## 2. Regras do projeto — as duas que mais quebram

Leia `AGENTS.md`. Repetindo o essencial porque ignorá-las custa retrabalho:

1. **Comentário no máximo 2 linhas, e só para o *por que* não óbvio.** Comentário que repete o código é ruído. Se o comportamento é verificável, escreva teste. O usuário já reclamou duas vezes nesta sessão por comentários enormes.
2. **Nenhum teste toca `~/.config/smartsec/`, keyring real ou rede real.** Para testar log ou trilha, use `orchestrator.scan_metadata()` (monta o `ScanMetadata` sem gravar) ou um `temp_dir()` próprio.

Comandos:

```bash
flock .git/smartsec-build.lock -c 'cargo build -j 1 --release'
cargo fmt --check
flock .git/smartsec-build.lock -c 'cargo clippy --all-targets -j 1 -- -D warnings'
flock .git/smartsec-build.lock -c 'cargo test -j 1 --bin smartsec'
```

**NUNCA** `cargo test` sem `--bin` — a suíte de integração executa o binário real contra Ollama e trava a máquina.

Rodar só `--bin smartsec` deixou o `--help` sem cobertura e o CI pegou três lacunas. As suítes que não tocam scanner (`tests/headless_signals.rs`, `tests/headless_exit_codes.rs`, `tests/history_cli.rs`, `tests/code_agent_integration.rs`, `tests/report_cli.rs`) leem o help e precisam rodar.

---

## 3. O que já está pronto

- **PR #105 aberto** contra `main`, MERGEABLE. Ainda não mergeado.
- **IA opcional.** `LlmConfig::default()` nasce sem provedor local; `is_configured()` falso com endpoint vazio e `validate()` retorna `Ok`. Scan funciona sem nenhuma IA.
- **Lista de provedores** com API primeiro, llama.cpp por último. `LlmProviderKind::index()` deriva a posição.
- **Trilha de auditoria da IA** (`src/code_agent/audit_trail.rs`): cada ação da IA vira uma linha JSON em `~/.config/smartsec/agent-trails/<scan_id>.jsonl`, escrita e descarregada na hora. `smartsec trace <SCAN_ID>` imprime. O log estruturado aponta para ela.
- **E2E fechado** na outra máquina: scan completo, 4 fases, relatório Markdown e PDF, com e sem IA.

---

## 4. TAREFA A — fechar o que está aberto

**A1. O agente de código não faz tool calling com a NIM.** Este é o único problema real da fase de IA. O scan com `nvidia/nemotron-3-super-120b-a12b` responde à análise de achados normalmente, mas na fase de agente de código o modelo **devolveu 0 tool calls** e a trilha registra `chamadas: 0` com `localizado: false`. O motivo registrado é "o modelo respondeu sem indicar arquivo e linha no código".

Diagnostique antes de mexer. Candidatas a verificar: o formato do payload de tools que o provedor envia; se `Meta-Llama-3.1-8B` (o default local) usa o schema de tool calling diferente do da OpenAI e se o provedor converte; se o prompt de工具 precisa ser diferente. Escreva um teste que reproduza e falhe antes de corrigir.

**A2. Verificar os 2 jobs do CI do PR #105** e corrigir o que falhar.

**A3. Mergear #105** quando os dois jobs estiverem verdes, e fechar as issues de Sprint 2. Só Sprint 3 fica aberta.

---

## 5. TAREFA B — implementar o CyberRAG

### 5.1 O que é

- Artigo: *Ontology-Aware RAG for Improved Question-Answering in Cybersecurity Education*
- Autores: Chengshuai Zhao, Garima Agrawal, Fan Zhang, Tharindu Kumarage, Zhen Tan, Yuli Deng, Ying-Chih Chen, Huan Liu (Arizona State University)
- arXiv: https://arxiv.org/abs/2412.14191
- Versão publicada: IEEE International Conference on Big Data (BigData) 2025, pp. 3161–3170, **DOI `10.1109/BigData66926.2025.11401740`**, publicado em 2025-12-08
- Código de referência: https://github.com/ChengshuaiZhao0/CyberRAG

### 5.2 Validação prévia — já feita, não precisa refazer

**Revisão por pares: CONFIRMADA.** O DOI do arXiv (`10.48550/arXiv.2412.14191`) é o DOI de preprint emitido pelo DataCite e não prova revisão por pares. A revisão se confirma pelo DOI da versão publicada no Crossref, da IEEE, numa conferência com revisão por pares. O artigo tem 31 citações.

**Licença do código: NÃO EXISTE.** O repositório de referência não tem arquivo `LICENSE` e a API do GitHub devolve `license: null`. Isso significa "todos os direitos reservados".

**Licença do artigo: CC BY 4.0** — o texto pode ser reutilizado com atribuição.

**Consequência prática, e ela é dura:** você **não pode copiar o código** do repositório de referência nem vendorizar arquivos dele. O que é legítimo — e o que deve ser feito — é **reimplementar a abordagem a partir do artigo**, que é CC BY 4.0, usando o repositório apenas como referência de leitura para entender os passos. Se em algum momento você se pegar copiando arquivo, pare e reescreva.

### 5.3Créditos — obrigatórios

Toda a documentação que você criar sobre isso tem de conter, no mínimo:

- Título completo do artigo
- Os oito autores
- Venue: IEEE International Conference on Big Data (BigData) 2025, pp. 3161–3170
- DOI `10.1109/BigData66926.2025.11401740`
- arXiv:2412.14191
- Link do código de referência, **deixando claro que é uma implementação independente de terceiros, não código copiado**
- Licença do artigo (CC BY 4.0) e o fato de o repositório de referência não ter licença

Sugestão: um `docs/cyberrag.md` com uma seção "Referências" e uma nota de que a implementação é própria, inspirada no artigo. Marque também no código, no ponto onde a validação por ontologia é usada, um comentário curto dizendo que o desenho vem do artigo com o DOI. **Esse comentário é dos poucos casos em que o AGENTS.md permite mais que 2 linhas**, porque registra origem intelectual e não é dedutível do código.

### 5.4 Qual dos dois: CyberRAG ou CyberBOT?

Comece lendo esta seção, porque ela muda o plano.

**CyberBOT** é a continuação do trabalho no ACM CIKM'25 (*CyberBOT: Ontology-Grounded Retrieval Augmented Generation for Reliable Cybersecurity Education*, DOI `10.1145/3746252.3761478`). Ele estende o CyberRAG adicionando um interpretador de intenção, um detector de pergunta de seguimento e um verificador de ontologia com escore contínuo em vez de validação seca.

**Verifiquei os dois repositórios. O dataset é o mesmo nos dois.** Ambos trazem `dataset/kb/kb.csv` com 2823 linhas, e a interseção entre os dois conjuntos é de 2823 — ou seja, são idênticos como conjunto, apenas embaralhados em ordem diferente. A ontologia também é quase a mesma: 26 triplas nos dois, e o CyberBOT acrescenta uma seção de Cloud Computing à cybersecurity.

**Consequência:** migrar para o CyberBOT **não compra um dado novo**. O que muda é o pipeline, não o corpus.

Escolha o **CyberRAG como base**, pelos seguintes motivos:

1. O pipeline é mais simples e cabe inteiro no que já existe. O ganho do CyberBOT está no turno de diálogo, e um TCC não precisa de multi-turno para responder "o que é isto e como corrijo".
2. Ele é o publicado com DOI de conferência revisada por pares que você foi pedido para implementar.
3. Adicionar o interpretador de intenção do CyberBOT depois é trivial, se sobrar tempo. Começar pelo mais simples e Validar é melhor do que começar pelo mais completo e não validar.

**Cite os dois no trabalho.** O CyberRAG é a base implementada; o CyberBOT mostra a direção do grupo de autores e é o que justifica dizer que o trabalho tem continuidade. Citar só o BigData e omitir o sucessor é desatualizar o próprio tema.

### 5.5 O que o artigo propõe

Pipeline de quatro passos:

1. **Recuperação** — embeddings da pergunta, busca os `top-k` mais similares numa base de conhecimento. O artigo usa Contriever, `k=1`.
2. **Geração** — contexto recuperado + pergunta num prompt, o modelo gera a resposta. O artigo usa Meta-Llama-3-8B-Instruct.
3. **Validação por ontologia** — a resposta gerada é verificada contra uma ontologia de segurança (o artigo instancia a partir do AISecKG). É esta etapa que reduz alucinação e uso indevido: se a resposta cai fora do escopo da ontologia, ela é rejeitada.
4. **Avaliação** — BERTScore, METEOR e ROUGE.

### 5.6 Onde isso encosta no smartsec — o caso de uso é educational, por achado

O caso de uso que interessa aqui é **explicar um achado ao usuário, com trecho do código dele**:

> operador clica num achado → o SmartSec explica o que é, por que é um problema, e mostra um exemplo ancorado no **trecho de código real do usuário**, retrieved de um dataset, para reduzir alucinação e erro.

Isso muda o encaixe em três pontos:

**1. A base de conhecimento não é um curso, é conhecimento de vulnerabilidade.** O `kb.csv` dos autores responde perguntas de aluno ("quais critérios definem a severidade?"). Para o SmartSec o corpus útil é: descrição de CWE, padrões de correção seguros, e ejemplos de código vulnerável por linguagem. **Construa esse corpus.** O `kb.csv` dos autores serve de referência de formato, não de conteúdo.

**2. O trecho do usuário entra como contexto de recuperação, não só na geração.** O pipeline do artigo recupera documentos do KB e gera. Aqui, além disso, o trecho real do achado — que o `code_audit` e o agente de código já localizam em arquivo e linha — deve ser recuperado junto, para que o exemplo exibido corresponda ao código que o usuário tem, e não a um exemplo genérico.

**3. A ontologia valida a explicação, e precisa haver uma noção de "não sei".** O ganho contra alucinação aqui é duplo: recuperar contexto relevante e recusar resposta fora do escopo. Uma explicação que a ontologia reprova tem de aparecer assim na tela — "não consegui explicar isto com segurança" — em vez de o modelo inventar. **Uma recusa é um resultado correto; uma alucinação com confiança é o pior desfecho possível numa ferramenta de segurança.**

### 5.7 Onde registrar o resultado da validação

A regra do projeto é que tudo que a IA faz fica registrado, e uma validação que reprova uma resposta é informação de auditoria:

- na **trilha de auditoria** (`src/code_agent/audit_trail.rs`)
- no **`ScanMetadata`**, junto de `llm_provider_effective` e `llm_failure_reason`, com um campo análogo para o resultado da ontologia
- na **TUI**, onde a fase de IA já é visível ao vivo

Três coisas para respeitar:

- **A ontologia não pode virar mais um gateway.** Você acabou de remover um bug em que a ausência de IA bloqueava o scan. A IA é complemento. Se a ontologia faltar ou falhar, o scan continua, e a trilha registra o motivo.
- **Nada de rede real nos testes.** A ontologia é um arquivo local; o teste carrega um fixture.
- **Documente o que foi adaptado e por quê.** O artigo é sobre *educação em segurança* e QA conversacional; o SmartSec é ferramenta de auditoria com achados estruturados e o caso de uso é a explicação por achado. Não é obrigatório casar 1:1.

### 5.8 Limitações conhecidas dos dados de referência

Registre estas limitações no seu relatório. Elas são reais e afetam qualquer avaliação que você faça:

- O `kb.csv` dos autores tem 2823 linhas, todas geradas por In-Context Learning, e cobre perguntas de aluno de curso de segurança — não vulnerabilidades específicas.
- A ontologia tem **26 triplas**. É pequena demais para validar subtileza. Uma explicação pode passar na ontologia e ainda assim estar errada. Trate a validação como **filtro de verdade grosseiro**, não como prova de correção.
- Não reproduza as métricas do artigo (BERTScore/METEOR/ROUGE) como se fossem resultado seu. Se avaliar, avalie **no seu corpus**, e diga explicitamente que os números não são comparáveis aos do artigo.

---

## 6. Como workingar

- Uma branch por tarefa, PR por tarefa. Nunca push na `main`.
- Commit e push pequenos, com a validação no corpo da mensagem. Se só compila, não commita.
- Se um passo não funcionar, **diga que não funcionou** e por quê. Não declare pronto o que não foi testado, e não esconda teste pulado.
- Se encontrar algo que contradiga este prompt, investigue e reporte em vez de seguir às cegas.

Comece pela **Tarefa A1** — é o problema real e com efeito no produto. A Tarefa B é grande; planeje e divida antes de codar.