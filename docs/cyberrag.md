# Explicação de achados com RAG e validação por ontologia (cyberrag)

## Referências

- **Artigo-base:** "Ontology-Aware RAG for Improved Question-Answering in
  Cybersecurity Education" — Chengshuai Zhao, Garima Agrawal, Fan Zhang,
  Tharindu Kumarage, Zhen Tan, Yuli Deng, Ying-Chih Chen, Huan Liu (Arizona
  State University).
- **Venue:** IEEE International Conference on Big Data (BigData) 2025,
  pp. 3161–3170.
- **DOI:** [10.1109/BigData66926.2025.11401740](https://doi.org/10.1109/BigData66926.2025.11401740)
  (versão revisada por pares). Preprint: [arXiv:2412.14191](https://arxiv.org/abs/2412.14191)
  — o DOI do preprint (`10.48550/arXiv.2412.14191`) não atesta revisão por pares.
- **Sucessor citado:** *CyberBOT: Ontology-Grounded Retrieval Augmented
  Generation for Reliable Cybersecurity Education* — ACM CIKM'25,
  DOI [10.1145/3746252.3761478](https://doi.org/10.1145/3746252.3761478).
  O dataset dos dois trabalhos é o mesmo (2.823 linhas de Q/A, interseção
  total); a diferença está no pipeline, não no corpus. O SmartSec implementa
  a base (CyberRAG) e registra o CyberBOT como direção de continuidade.

## Natureza desta implementação

Esta é uma **implementação independente**, inspirada no artigo e reimplementada
a partir do texto (licença do artigo: **CC BY 4.0**, reutilizável com
atribuição). O repositório de código de referência
(`github.com/ChengshuaiZhao0/CyberRAG`) **não possui licença** (`license: null`
na API do GitHub — "todos os direitos reservados") e **nada dele foi copiado**:
nem código, nem prompts, nem dataset, nem arquivo de ontologia. Corpus e
ontologia do SmartSec são autorais.

## O que o pipeline faz aqui

1. **Recuperação** — a consulta é montada do achado (título, descrição,
   evidência) **e do trecho real do código do usuário** (`code_location`), e
   busca os documentos mais relevantes no corpus próprio.
2. **Geração** — o contexto recuperado + o trecho do usuário + o vocabulário
   fechado da ontologia entram no prompt; o modelo responde em JSON estrito
   (explicação em prosa + conceito + afirmações em triplas).
3. **Validação por ontologia** — cada afirmação é conferida contra as triplas
   da ontologia (resolução por id ou rótulo, caixa/acento-insensível). Uma
   tripla inexistente reprova; após um retry corretivo, a explicação é
   **recusada** com motivo — "não consegui explicar isto com segurança" — em
   vez de ser exibida como confiável.
4. **Avaliação** — fora do escopo desta entrega. Se realizada, será feita
   **no corpus do SmartSec**, e os números **não serão comparáveis** aos do
   artigo (BERTScore/METEOR/ROUGE de lá não são resultado deste trabalho).

## Adaptações em relação ao artigo (e por quê)

| Dimensão | Artigo | SmartSec |
|---|---|---|
| Validação por ontologia | Juiz-LLM com a ontologia como rubrica textual, devolvendo `(Pass/Not Pass, score)`; veredito seco e, no código publicado, nem lido (`answer_filter` inerte) | Validação **simbólica determinística** das afirmações contra triplas locais, com retry corretivo e recusa registrada |
| Recuperação | Contriever (dual-encoder denso), documentos = pergunta+resposta de um KB de Q/A de curso, k=1 | BM25 lexical offline (default) e embeddings via provedor quando configurado; documentos são unidades de conhecimento de vulnerabilidade; top-k configurável |
| Corpus | 2.823 pares Q/A sintéticos gerados por in-context learning, para perguntas de aluno | 20 classes de fraqueza (CWE) com padrão seguro e exemplos vulnerável/corrigido por linguagem, autorais, voltados a explicar **achados** |
| Ontologia | 26 triplas / 7 relações destiladas de AISecKG | 86 triplas / 3 relações autorais, versionadas no próprio repositório |
| Recusa | "Not Pass" seco (sem UX); sem caminho de recusa descrito na interface | Tela mostra a recusa com o motivo; a trilha e o log estruturado registram o veredito |

## Limitações (reais, declaradas)

- **A cobertura da ontologia é finita e pequena.** Passar na validação é um
  **filtro grosso de pertinência**, não prova de correção: uma explicação pode
  citar apenas triplas existentes e ainda estar errada. O artigo-base tem 26
  triplas; esta implementação tem 86 — mais cobertura, mesma natureza grosseira.
- O juiz-LLM do artigo mede sobretudo **domínio**, não veracidade; a adaptação
  simbólica troca essa fragilidade por **rigidez**: paráfrases legítimas que não
  casem com o vocabulário são recusadas (recusar demais é aceitável; inventar
  não é).
- As métricas do artigo **não foram reproduzidas** e não são comparáveis.
- Embeddings via provedor dependem de modelo/configuração externa; o caminho
  offline é o lexical.

## Onde o resultado fica registrado

- **Trilha de auditoria** (JSONL append-only, por scan).
- **Log estruturado** (`ScanMetadata`), com o veredito ao lado de
  `llm_provider_effective`/`llm_failure_reason`.
- **TUI**, no detalhe do achado, incluindo a recusa.

A ontologia **nunca é gateway**: ausência ou falha dela não impede o scan nem
derruba a fase — o motivo é registrado e a explicação é recusada com
honestidade.
