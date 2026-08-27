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
