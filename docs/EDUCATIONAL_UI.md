# Tela de explicação educacional — decisões de design

Base consultada (out/2026):

- **Worked-example effect / Cognitive Load Theory (Sweller; Renkl)**: estudar
  exemplos resolvidos reduz carga extrínseca e ajuda o novato a formar o
  esquema antes de resolver sozinho. Por isso a tela mantém, lado a lado, o
  trecho **vulnerável** e o **corrigido**.
- **Segmentação e sinalização (Mayer/CLT)**: conteúdo em blocos curtos com
  títulos explícitos (“o que aconteceu”, “como corrigir”, “como verificar”)
  reduz carga e melhora transferência.
- **Self-explanation / retrieval practice**: pedir que o aprendiz explique com
  as próprias palavras e tente recuperar a ideia sem reler fortalece a
  retenção. A tela termina com uma pergunta curta de fixação.
- **Scaffolding**: a correção aparece em passos pequenos e o exemplo corrigido
  vem depois do problema, não antes.
- **Dual coding**: texto curto + código real + cores de sintaxe; a mesma ideia
  em duas representações.

## Estrutura da tela

1. Cabeçalho do achado: severidade, ferramenta, arquivo:linha.
2. **1. O que aconteceu e por que importa** — texto da IA em linguagem direta.
3. **2. Do vulnerável ao corrigido** — blocos `vulnerável`/`corrigido` e o
   `padrão seguro`.
4. **3. Como verificar** — o teste/observação que confirma a correção.
5. **4. Para lembrar · triplas da ontologia** — conceito, veredito e triplas da
   ontologia (fundamentação).
6. **Pergunta de fixação** — uma frase para o usuário explicar por que o
   exemplo vulnerável falha.

Quando a explicação é recusada, a seção 1 mostra o motivo e a seção 4 mantém a
fundamentação; nenhuma das duas desaparece.

## Regras de apresentação

- Linhas de código longas **quebram** em várias linhas visuais; nunca são
  cortadas com `…`.
- Linhas de continuação usam o mesmo gutter, sem repetir o número da linha.
- A linha-alvo continua destacada em todas as linhas visuais que ela ocupar.
- O painel se chama **Explicação educacional**.
- A lista de achados mostra `severidade · ferramenta · título · arquivo:linha`
  para que a origem seja identificável sem abrir o detalhe.
