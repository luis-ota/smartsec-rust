# Resumo das alteracoes

## O que foi feito

- Adicionei um plano dinamico para Nuclei baseado nos logs do Nmap.
- Reativei o Nmap no catalogo de ferramentas e passei a registrar sua saida como entrada da decisao.
- Inclui validacao de politica segura para aceitar apenas perfis, concorrencia e timeout permitidos.
- Adicionei fallback deterministico quando a IA nao responde ou tenta propor algo invalido.
- Passei a persistir a decisao, a justificativa, o modelo usado, as evidencias e os parametros aplicados.
- Atualizei o relatorio Markdown para expor a trilha de auditoria da decisao dinamica.
- Adicionei testes cobrindo decisao valida, decisao invalida e fallback.

## Por que foi feito

- Para atender os requisitos REQ10 e REQ12, que pedem interpretacao de logs por IA e decisao dinamica dos proximos passos.
- Para evitar que a IA injete comandos arbitrarios ou escolha parametros fora de uma politica segura.
- Para garantir que duas saidas distintas do Nmap possam gerar planos distintos e auditaveis.
- Para tornar o fluxo reproduzivel, mesmo quando a IA falha ou retorna algo fora do esperado.

## Observacao de validacao

- Os testes nao puderam ser executados no ambiente porque a toolchain Rust nao esta instalada no PATH desta maquina.
- A validacao de diagnostico do editor nao apontou erros nos arquivos alterados.