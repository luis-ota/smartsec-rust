# Distribuicao da Sprint 1

Primeira divisao de trabalho entre os tres desenvolvedores. As Sprints 2 e 3 serao distribuidas depois do aceite da Sprint 1.

## Luis Otavio Silva Santos

Responsavel geral e lider tecnico. Assume as partes core e de maior risco:

- #4 Implementar executor Podman rootless
- #6 Integrar Nmap ao pipeline real
- #10 Consolidar provedores de IA remoto e local com seguranca
- #13 Robustecer a integracao real com Nuclei

## Passossss

Responsavel pela camada de produto e persistencia operacional:

- #3 Implementar CLI estruturada e configuracao de execucao
- #7 Persistir logs estruturados e metadados dos scans
- #12 Separar modos real e demonstrativo e rastrear a origem dos achados

## VictorCMoro

Responsavel por rastreabilidade e qualidade:

- #2 Alinhar documentacao e criar matriz de rastreabilidade
- #9 Implementar decisao dinamica inicial entre Nmap e Nuclei
- #11 Criar testes e evidencia de aceite da Sprint 1

## Dependencias de runtime

A distribuicao e um binario Linux unico. O binario nao deve depender de
biblioteca, fonte ou servico instalado no host alem do Podman rootless.

- **Fonte de relatorio:** `assets/fonts/NotoSans-Regular.ttf` e embutida no
  binario por `include_bytes!`, com a licenca SIL OFL 1.1 em
  `assets/fonts/LICENSE`. O arquivo precisa estar versionado: sem ele a
  compilacao falha, e ele nao pode ser gerado em tempo de build, senao uma
  maquina limpa constroi um binario diferente do oficial. As 14 fontes padrao do
  PDF nao tem `cmap` Unicode e produziriam caracteres quebrados em portugues.
- **Geracao de PDF:** `printpdf` 0.12.8 (MIT) com `default-features = false`.
  As features padrao ligam `azul-layout`, `azul-css`, `xmlparser` e
  `rust-fontconfig`; este ultimo descobre fontes lendo a configuracao de
  fontconfig do host, o que tornaria o relatorio dependente do ambiente. Como o
  PDF nao usa nenhum desses recursos, eles ficam desligados.
- **Sem binario externo:** o PDF e escrito pelo proprio `printpdf` e relido
  pelos testes com o parser da propria biblioteca. Nao ha `pdftotext`,
  `mutool` ou `poppler` em nenhum caminho de build, teste ou execucao.

## Regras

- Cada integrante e responsavel primario pelas issues atribuidas.
- Toda alteracao entra por pull request; nao ha push direto na `main`.
- O PR deve referenciar a issue e incluir testes ou evidencia correspondente.
- Luis revisa arquitetura, modelo de dados, seguranca, IA e contratos do pipeline.
- Passossss revisa CLI, TUI, relatorios e fluxos de uso.
- Victor revisa testes, reproducibilidade e evidencias de aceite.
- Mudancas fora da issue devem ser discutidas antes de implementadas.

| Integrante | Issues |
|---|---:|
| Luis | 4 |
| Passossss | 3 |
| VictorCMoro | 3 |
