# Auditoria de código: taxa de falso positivo

Medição sobre o detector determinístico de código-fonte antes de ele entrar no
pipeline. O resultado motivou desligar uma das duas regras.

## Método

O detector rodou sobre Python real da máquina, sem rede e sem alterar nada:

| Fonte | Arquivos |
|---|---:|
| `/usr/lib/python3.14` (stdlib) | 4.187 |
| `~/.local` (Python 3.8/3.11/3.12, PyCharm, debugpy) | 3.404 |
| `/opt/cuda` | 402 |
| `~/dev/saas-14.1/migration` (migração de banco) | 372 |
| `/usr/share`, `~/dev` | 19 |
| **total** | **8.384** |

**3.105.085 linhas.** Todos os 98 achados foram classificados um a um — sem
amostra, sem "incerto": em cada caso o valor foi seguido até a origem
(variável, ambiente, banco, arquivo) para dar veredito.

## Resultado

```
achados: 98 (94 com dedup por hash de conteúdo)

sql-injection:  73 achados →  0 verdadeiros, 73 falsos   taxa FP = 100%
credential:      25 achados →  7 verdadeiros, 18 falsos   taxa FP =  72%
```

## Injeção de SQL: 100% de falso positivo

Nenhum exploitable em 3,1 milhões de linhas, apesar de o corpus incluir código
real de migração de banco. As cinco fontes:

| Fonte | FP | Causa |
|---|---:|---|
| `self.execute(...)` do `distutils`/`setuptools` | 17 | casa pelo nome do método, ignora o receptor |
| migração Odoo: valores vindo de `fetchall()` | 32 | concatena dado do próprio banco, sem entrada externa |
| `gdb.execute(...)` | 9 | é o debugger, não é banco |
| internos do `sqlite3` (`q`, `sql`, já citado) | 7 | sem resolução de binding |
| `coverage`, `yt_dlp`, Django `ManagementUtility` | 8 | mesmo nome de método, outro domínio |

Falso positivo reproduzido isoladamente:

```python
self.execute(os.unlink, (self.target,), "Removing " + self.target)
gdb.execute("set sysroot %s" % os.environ["ENV_PREFIX"])
conn.db1.execute(params)   # params é constante definida 5 linhas acima
```

## Credencial: 72% de falso positivo, com 7 verdadeiros reais

Os 7 verdadeiros confirmados, incluindo um do próprio código auditado:

| Local | Credencial |
|---|---|
| `~/dev/saas-14.1/migration/connection.py:48` | `password='odoo@dev'` |
| `yt_dlp/shahid.py:27` | par `access_key` + `secret_key` AWS |
| `yt_dlp/npr.py:66`, `wykop.py:25`, `canalsurmas.py:36` | `apiKey` e `password` |
| `yt_dlp/weverse.py:62`, `tver.py:312` | header de segredo, `api_key` |

Os 18 falsos: docstring de exemplo da própria stdlib, dicionário de índice de
módulos (`'pwd': 'pwd#module-pwd'`), anotação de tipo
(`secret: 'virSecret'`), regex multilinha `"""..."""` tokenizada como código, e
`password = "changeme"`.

## Defeito mais grave: a linha reportada estava errada em 62%

O detector reportava o início do statement, não a linha do token:

- `sql-injection`: 9 de 73 apontavam para a linha real
- `credential`: 9 de 25

```
connection.py:48 reportado → a senha real está na linha 47
shahid.py:27 reportado     → access_key real na linha 39
tver.py:321 reportado      → api_key real na linha 349
```

Para auditoria de credencial é o pior modo de falha possível: o auditor abre a
linha, **não vê a senha**, e marca como falso. Corrigido: a linha reportada é a
do token.

## Decisão

**A regra de injeção de SQL foi desligada.** Emitir 73 achados com 0 verdadeiro
positivo treina o revisor a descartar a ferramenta, e torna a densidade de
achados do TCC uma métrica sem significado de segurança. A regra permanece no
código, coberta por teste, fora do caminho de emissão.

A detecção volta sobre o módulo `ast` do próprio Python, que resolve receptor,
binding e linha exata. Uma tentativa de reescrita foi feita e **não passou na
validação** (o script devolvia lista vazia e erro numa injeção real), então foi
descartada em vez de ser entregue pela metade.

## Reprodução

O corpus é a instalação local do Python. O detector é exercitado por teste
auxiliar que chama `python::scan` e imprime arquivo, linha, regra e a linha de
código. Nada de produção foi tocado durante a medição, e nenhum teste escreve em
`~/.config/smartsec/config.toml` nem no keyring.
