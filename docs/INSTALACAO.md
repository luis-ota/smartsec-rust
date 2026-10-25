# Instalacao

Como instalar o SmartSec em um PC qualquer, sem `sudo` no caminho normal.

O binario sozinho nao roda: o TCC exige **Podman rootless** como engine disolamento (nao Docker), o backend de rede **`pasta`** e os **templates do
Nuclei**. O instalador verifica os tres e diz o que falta, com o comando
correto para a sua distro.

## Caminho rapido (um comando, sem `sudo`)

```bash
curl -fsSL https://github.com/luis-ota/smartsec-rust/releases/latest/download/install.sh | sh
```

O script baixa o pacote da sua arquitetura (`x86_64` ou `aarch64`), confere o
`SHA256SUMS` publicado, instala `smartsec` em `~/.local/bin` e verifica Podman
rootless, o backend de rede `pasta` e os templates do Nuclei — dizendo o que
falta com o comando correto para a sua distro.

| Variavel de ambiente | Efeito |
|---|---|
| `SMARTSEC_VERSION` | Fixa a versao (ex. `v0.2.0`); padrao: a mais recente |
| `SMARTSEC_INSTALL_DIR` | Destino do binario (padrao: `~/.local/bin`) |

Na primeira vez, vale inspecionar antes de executar:

```bash
curl -fsSL https://github.com/luis-ota/smartsec-rust/releases/latest/download/install.sh -o install.sh
less install.sh
sh install.sh
```

O pacote pronto exige Linux com **glibc 2.35 ou superior** (Ubuntu 22.04+,
Debian 12+, Fedora 36+, Arch). A chave da API fica em `auth.json` 0600; não há
dependência de `libdbus`/keyring. Distros mais antigas: compile do código, no
caminho abaixo.

## Caminho de desenvolvimento (compilar do codigo)

```bash
git clone https://github.com/luis-ota/smartsec-rust
cd smartsec-rust
./scripts/install.sh
```

O script instala `smartsec` em `~/.local/bin` (ou em `$XDG_BIN_HOME`).
Nenhum passo exige `sudo`.

Para ver o que aconteceria sem alterar nada:

```bash
./scripts/install.sh --dry-run
```

Depois:

```bash
smartsec --version
```

Se `~/.local/bin` nao estiver no `PATH`, o instalador avisa e mostra a linha
para acrescentar:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Opcoes do instalador

| Opcao | Efeito |
|---|---|
| `--dry-run` | Mostra o plano e nao escreve nada |
| `--check` | So verifica os pre-requisitos de runtime; sai `1` se faltar algo |
| `--build` | Compila a partir do codigo em vez de usar um binario pronto |
| `--bin <ARQUIVO>` | Instala um binario ja compilado (artefato de release) |
| `--prefix <DIR>` | Destino da instalacao, no lugar de `~/.local/bin` |
| `--self-test` | Roda os testes da logica de deteccao do proprio script |
| `--help`, `--version` | Ajuda e versao do instalador |

Rodar duas vezes e seguro: o instalador sobrescreve o binario e refaz o
symlink do alias.

## Pre-requisitos por distro

O Rust so e necessario para **compilar** o codigo. Quem instala um artefato
pronto nao precisa dele.

| Distribuicao | Podman + pasta | Rust (para compilar) |
|---|---|---|
| Debian, Ubuntu, Mint, Pop, Kali | `sudo apt-get install -y podman passt` | `sudo apt-get install -y cargo rustc` |
| Fedora, RHEL, Rocky, AlmaLinux | `sudo dnf install -y podman passt` | `sudo dnf install -y cargo rust` |
| Arch, Manjaro, EndeavourOS | `sudo pacman -S podman passt` | `sudo pacman -S rust` |
| openSUSE, SLES | `sudo zypper install -y podman passt` | `sudo zypper install -y cargo rust` |
| macOS | `brew install podman` (experimental, veja abaixo) | `brew install rust` |

Rust 1.80+ e o minimo. Pelo `rustup` funciona em qualquer uma delas:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Templates do Nuclei

O executor monta os containers com os templates em `~/nuclei-templates`, no
commit fixado em `src/tools/nuclei.rs` (`NUCLEI_TEMPLATES_COMMIT`):

```bash
git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
git -C ~/nuclei-templates checkout b98e6097cb84e73e7a480436062d685a8f898824
```

Para usar outro caminho, aponte `nuclei_templates_path` no
`smartsec.toml` (veja [CONFIGURACAO.md](CONFIGURACAO.md)). O instalador aceita
tambem `SMARTSEC_NUCLEI_TEMPLATES` para checar um caminho especifico.

## Podman sem rootless

O `--network pasta` que o executor usa nao funciona em modo root, entao um
Podman instalado como root **nao serve** — o scan falha com erro de rede, nao com uma mensagem sobre privilegios.

Checagem:

```bash
podman info --format '{{.Host.Security.Rootless}}'
```

A saida precisa ser `true`. Se for `false`, o pacote instalado normalmentainda nao tem os intervalos de usuario que o rootless exige:

```bash
sudo modprobe overlay
sudo modprobe br_netfilter
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
```

Depois disso e obrigatorio **reconectar a sessao** (logout e login, ou abrir
um novo terminal) — os intervalos so valem para processos novos. Se ainda
assim `podman info` nao confirmar rootless, o container de exemplo abaixo
mostra onde doeu:

```bash
podman run --rm --network pasta alpine tru```

Um `pasta` antigo tambem quebra o scan: o executor passa
`--map-host-loopback=169.254.1.2` e versoes antigas do `passt` nao conhecem a
opcao. O instalador detecta e avisa. No Ubuntu 24.04 ou superior, o container
tambem precisa da configuracao de rede:

```ini
# ~/.config/containers/containers.conf
[network]
network_cmd = "pasta"
```

## Instalar um artefato pronto

**Procedimento de release:** atualize `version` no `Cargo.toml`, commite e crie a tag `vX.Y.Z`; o workflow confere se o binário reporta a mesma versão da tag antes de publicar (a `v0.2.1` saiu com o binário reportando `0.2.0` e essa guarda existe para isso não repetir).

Cada tag `v*` publica `.tar.gz` para Linux, um `.deb` para Ubuntu/Debian e os
checksums SHA256 em `SHA256SUMS` (o `install.sh` do `curl | sh` tambem e um
asset). Pelo bootstrap:

```bash
SMARTSEC_VERSION=v0.2.0 sh install.sh --prefix ~/.local/bin
```

Ou manualmente, para conferir antes:

```bash
curl -LO https://github.com/luis-ota/smartsec-rust/releases/download/v0.2.0/smartsec-0.2.0-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/luis-ota/smartsec-rust/releases/download/v0.2.0/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf smartsec-0.2.0-x86_64-unknown-linux-gnu.tar.gz
./install.sh --bin ./smartsec
```

O `.deb` tambem instala sem passar pelo script, mas precisa de `sudo` porque
`dpkg` escreve em `/usr`:

```bash
sudo dpkg -i smartsec_0.2.0_amd64.deb
```

## Verificar que deu certo

```bash
smartsec --version
smartsec --help
```

O `--version` precisa responder `smartsec <versao>` e o comando precisa existir no
`PATH`. Para checar o runtimtodo de uma vez:

```bash
smartsec scan --target http://169.254.1.2:3000
```

Um alvo em `127.0.0.1:3000` da propria maquina e o alvo autorizado ddemonstracao: o Podman rootless mapeia o loopback do host para `169.254.1.2`
dentro do container, entao o alvo autorizado nao e exposto na rede local.
Para uma varredura real, use `--config` com um arquivo TOML valido.

## Desinstalar

O instalador nao escreve fora de `~/.local/bin` e do `~/.config/smartsec`:

```bash
rm -f ~/.local/bin/smartsec
```

Se quiser apagar tambem configuracao e historico de execucoes:

```bash
rm -rf ~/.config/smartsec
```

Para remover tudo de uma vez, mais o que o proprio script instalou:

```bash
sudo dpkg -r smartsec          # se instalou pelo .deb
```

Os templates do Nuclei e o Podman **nao** sao removidos: sao dependencias
compartilhadas com outras ferramentas, e o instalador nao os instalou.

## macOS

Suporte experimental. O TCC valida Podman rootless no Linux, e no macOS o
Podman roda dentro de uma maquina virtual (`podman machine init`), o que muda o
modelo de isolamento. O instalador instala o binario e avisa que o ambientnao e o validado. A alternativa honesta e rodar em Linux, que e a plataforma
do TCC.
