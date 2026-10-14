#!/usr/bin/env bash
# Instalador do SmartSec para usuario final, sem privilegios de root.
#
# O binario e Single, mas o runtime nao: o TCC exige Podman rootless, o backend
# de rede `pasta` e os templates do Nuclei. O script instala o executavel em
# ~/.local/bin e reporta o que falta em vez de deixar o primeiro scan falhar.

set -euo pipefail

readonly VERSAO_SCRIPTO="1.0.0"
readonly COMANDO="smartsec"
readonly REPO_NUCLEI="https://github.com/projectdiscovery/nuclei-templates"
readonly COMMIT_NUCLEI="b98e6097cb84e73e7a480436062d685a8f898824"

MODO_DRY_RUN=0
MODO_SO_CHECAGEM=0
MODO_COMPILAR=0
MODO_TESTE=0
BINARIO_FONTE=""
PASTA_ALVO=""

log() { printf '%s\n' "$*"; }
aviso() { printf 'aviso: %s\n' "$*" >&2; }
erro() { printf 'erro: %s\n' "$*" >&2; }

die() {
    erro "$*"
    exit 1
}

# ── Deteccao pura (testada por --self-test) ─────────────────────────────────

classificar_os() {
    case "${1:-}" in
        Linux) printf 'linux\n' ;;
        Darwin) printf 'macos\n' ;;
        *) printf 'desconhecido\n' ;;
    esac
}

classificar_arq() {
    case "${1:-}" in
        x86_64 | amd64) printf 'x86_64\n' ;;
        aarch64 | arm64) printf 'aarch64\n' ;;
        *) printf 'desconhecido\n' ;;
    esac
}

# FAMILIA_DISTRO vira a chave da tabela de instrucoes em `instrucoes_podman`.
classificar_distro() {
    case "${1:-}" in
        fedora | rhel | centos | rocky | almalinux) printf 'rhel\n' ;;
        arch | manjaro | endeavouros) printf 'arch\n' ;;
        opensuse* | sles | suse) printf 'suse\n' ;;
        debian | ubuntu | linuxmint | pop | elementary | kali) printf 'debian\n' ;;
        *) printf 'desconhecido\n' ;;
    esac
}

carregar_os_release() {
    [ -r "${SMARTSEC_OS_RELEASE:-/etc/os-release}" ] || return 0
    # shellcheck disable=SC1091
    . "${SMARTSEC_OS_RELEASE:-/etc/os-release}"
}

detectar_id_distro() {
    local id
    carregar_os_release
    id="${ID:-}"
    printf '%s\n' "${id:-desconhecido}"
}

detectar_familia_distro() {
    local familia
    carregar_os_release
    familia="$(classificar_distro "${ID:-}")"
    if [ "$familia" != "desconhecido" ]; then
        printf '%s\n' "$familia"
        return 0
    fi
    # Distribuicoes que nao trazem ID conhecido costumam declarar ID_LIKE;
    # e ele quem decide a familia de pacotes.
    case " ${ID_LIKE:-} " in
        *" debian "*) familia=debian ;;
        *" fedora "* | *" rhel "*) familia=rhel ;;
        *" arch "*) familia=arch ;;
        *" suse "* | *" opensuse "*) familia=suse ;;
    esac
    printf '%s\n' "$familia"
}

instrucoes_podman() {
    case "${1:-}" in
        debian)
            printf 'sudo apt-get install -y podman passt\n'
            printf 'Para o Ubuntu 24.04 ou superior, crie ~/.config/containers/containers.conf:\n'
            printf '[network]\nnetwork_cmd = "pasta"\n'
            ;;
        rhel)
            printf 'sudo dnf install -y podman passt\n'
            ;;
        arch)
            printf 'sudo pacman -S podman passt\n'
            ;;
        suse)
            printf 'sudo zypper install -y podman passt\n'
            ;;
        *)
            printf 'Instale o Podman 4+ e o pacote que fornece o binario pasta (passt).\n'
            ;;
    esac
}

instrucoes_rust() {
    case "${1:-}" in
        debian)
            printf 'sudo apt-get install -y cargo rustc\n'
            printf 'Ou, preferencialmente: curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh\n'
            ;;
        rhel)
            printf 'sudo dnf install -y cargo rust\n'
            printf 'Ou: curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh\n'
            ;;
        arch)
            printf 'sudo pacman -S rust\n'
            ;;
        suse)
            printf 'sudo zypper install -y cargo rust\n'
            ;;
        *)
            printf 'Instale o Rust 1.80+ pelo rustup: https://rustup.rs\n'
            ;;
    esac
}

# ── Pre-requisitos ──────────────────────────────────────────────────────────

pasta_suporta_loopback() {
    pasta --help 2>&1 | grep -q -- '--map-host-loopback'
}

podman_e_rootless() {
    local valor
    valor="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" || return 1
    [ "$valor" = "true" ]
}

caminho_templates() {
    printf '%s\n' "${SMARTSEC_NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"
}

status_podman() {
    if ! command -v podman >/dev/null 2>&1; then
        printf 'ausente\n'
    elif podman_e_rootless; then
        printf 'ok\n'
    elif [ "$(id -u)" = "0" ]; then
        printf 'root\n'
    else
        printf 'nao-rootless\n'
    fi
}

status_pasta() {
    if ! command -v pasta >/dev/null 2>&1; then
        printf 'ausente\n'
    elif pasta_suporta_loopback; then
        printf 'ok\n'
    else
        printf 'antigo\n'
    fi
}

status_templates() {
    local pasta_templates
    pasta_templates="$(caminho_templates)"
    if [ -d "$pasta_templates/http" ] || [ -d "$pasta_templates/dns" ]; then
        printf 'ok\n'
    elif [ -d "$pasta_templates" ]; then
        printf 'vazio\n'
    else
        printf 'ausente\n'
    fi
}

# Os tres status sao lidos numa unica chamada porque `podman info` demora e a
# checagem roda varias vezes (--dry-run, --check e a installacao de verdade).
levantar_pre_requisitos() {
    log "Pre-requisitos"
    log "  sistema      $(classificar_os "$(uname -s)") $(classificar_arq "$(uname -m)")"
    log "  distribuicao $(detectar_id_distro) (pacotes: $(detectar_familia_distro))"

    local familia podman pasta_status templates pendentes=0
    familia="$(detectar_familia_distro)"
    podman="$(status_podman)"
    pasta_status="$(status_pasta)"
    templates="$(status_templates)"

    case "$podman" in
        ok) log "  podman       ok (rootless)" ;;
        nao-rootless)
            log "  podman       ATENCAO: instalado, porem sem modo rootless"
            pendentes=$((pendentes + 1))
            ;;
        root)
            log "  podman       ATENCAO: a sessao atual e root, entao nao prova rootless"
            pendentes=$((pendentes + 1))
            ;;
        *)
            log "  podman       FALTA"
            pendentes=$((pendentes + 1))
            ;;
    esac

    case "$pasta_status" in
        ok) log "  pasta        ok" ;;
        antigo)
            log "  pasta        ATENCAO: versao sem --map-host-loopback, exigida pelo executor"
            pendentes=$((pendentes + 1))
            ;;
        *)
            log "  pasta        FALTA"
            pendentes=$((pendentes + 1))
            ;;
    esac

    case "$templates" in
        ok) log "  templates    ok ($(caminho_templates))" ;;
        vazio)
            log "  templates    ATENCAO: $(caminho_templates) existe mas nao tem os templates Nuclei"
            pendentes=$((pendentes + 1))
            ;;
        *)
            log "  templates    FALTA ($(caminho_templates))"
            pendentes=$((pendentes + 1))
            ;;
    esac

    PRE_REQUISITOS_PENDENTES="$pendentes"
    PRE_REQUISITOS_FAMILIA="$familia"
}

explicar_pre_requisitos() {
    local familia="${PRE_REQUISITOS_FAMILIA:-desconhecido}"
    log ""
    log "Como resolver"
    log "  Podman rootless e o engine de isolamento do TCC; Docker nao serve."
    log "  No Linux sem subsistema de usuario nao basta instalar o pacote:"
    log "  o rootless precisa de /etc/subuid e /etc/subgid do usuario."
    log ""
    log "  $ sudo modprobe overlay && sudo modprobe br_netfilter"
    log "  $ sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 \"\$USER\""
    log "  (depois de editar, e necessario reconectar a sessao)"
    log ""
    log "  Instalacao dos pacotes:"
    instrucoes_podman "$familia" | sed 's/^/  /'
    log ""
    log "  Templates do Nuclei (o codigo fixa o commit $COMMIT_NUCLEI):"
    log "  \$ git clone $REPO_NUCLEI \"$(caminho_templates)\""
    log "  \$ git -C \"$(caminho_templates)\" checkout $COMMIT_NUCLEI"
    log "  Ou aponte nuclei_templates_path no smartsec.toml para outra pasta."
}

# ── Binario ─────────────────────────────────────────────────────────────────

resolver_binario_fonte() {
    local raiz release debug
    raiz="$(raiz_do_repo)"
    if [ -n "$BINARIO_FONTE" ]; then
        [ -x "$BINARIO_FONTE" ] || die "binario invalido: $BINARIO_FONTE"
        printf '%s\n' "$BINARIO_FONTE"
        return 0
    fi
    release="$raiz/target/release/$COMANDO"
    debug="$raiz/target/debug/$COMANDO"
    if [ -x "$release" ]; then
        printf '%s\n' "$release"
    elif [ -x "$debug" ]; then
        printf '%s\n' "$debug"
    else
        printf '\n'
    fi
}

# Procura a raiz do repositorio a partir da propria copia do script, e nao do
# diretorio atual: `bash /caminho/para/scripts/install.sh` de outro lugar ainda
# precisa achar `target/release` e o `Cargo.toml`.
raiz_do_repo() {
    local diretorio
    diretorio="$(dirname "$0")"
    while [ "$diretorio" != "/" ] && [ "$diretorio" != "." ]; do
        if [ -f "$diretorio/Cargo.toml" ] && [ -d "$diretorio/src" ]; then
            printf '%s\n' "$diretorio"
            return 0
        fi
        diretorio="$(dirname "$diretorio")"
    done
    printf '%s\n' "$PWD"
}

compilar_binario() {
    local raiz
    raiz="$(raiz_do_repo)"
    [ -f "$raiz/Cargo.toml" ] || die "compilar exige o repositorio (nenhum Cargo.toml acima de $0)"
    command -v cargo >/dev/null 2>&1 || {
        instrucoes_rust "${PRE_REQUISITOS_FAMILIA:-desconhecido}" >&2
        die "cargo nao encontrado: instale o Rust para compilar a partir do codigo"
    }
    # A mensagem vai para stderr porque o valor de retorno desta funcao e o
    # caminho do binario, que o plano de instalacao imprime.
    printf 'Compilando com cargo build --release (pode levar alguns minutos)\n' >&2
    if [ "$MODO_DRY_RUN" -eq 1 ]; then
        printf '%s\n' "$raiz/target/release/$COMANDO"
        return 0
    fi
    # `-j 1` porque o build em paralelo estoura a memoria das maquinas de
    # desenvolvimento do projeto (README, secao Validacao).
    (cd "$raiz" && cargo build -j 1 --release) || die "cargo build falhou"
    printf '%s\n' "$raiz/target/release/$COMANDO"
}

resolver_binario_dir() {
    local base
    base="$(destino_bin)"
    if [ "$MODO_DRY_RUN" -eq 1 ]; then
        printf '%s\n' "$base"
        return 0
    fi
    [ -d "$base" ] || mkdir -p "$base" || die "nao foi possivel criar $base"
    printf '%s\n' "$base"
}

destino_bin() {
    if [ -n "$PASTA_ALVO" ]; then
        printf '%s\n' "$PASTA_ALVO"
    elif [ -n "${XDG_BIN_HOME:-}" ]; then
        printf '%s\n' "$XDG_BIN_HOME"
    elif [ -n "${HOME:-}" ] && [ -w "${HOME:-}" ]; then
        printf '%s\n' "$HOME/.local/bin"
    else
        die "sem \$HOME gravavel: informe --prefix <DIR>"
    fi
}

caminho_no_path() {
    local diretorio="$1" entrada IFS=':'
    for entrada in $PATH; do
        [ "$entrada" = "$diretorio" ] && return 0
    done
    return 1
}

instalar() {
    local binario base destino
    binario="$(resolver_binario_fonte)"

    if [ "$MODO_COMPILAR" -eq 1 ] || [ -z "$binario" ]; then
        if [ -z "$binario" ]; then
            log "Nenhum binario compilado encontrado; compilando a partir do codigo" >&2
        fi
        binario="$(compilar_binario)"
    fi

    base="$(resolver_binario_dir)"
    destino="$base/$COMANDO"

    log ""
    log "Instalacao"
    log "  origem       $binario"
    log "  destino      $destino"

    if [ "$MODO_DRY_RUN" -eq 1 ]; then
        log "  acao         dry-run: nada foi escrito"
    else
        [ -f "$binario" ] || die "binario nao encontrado em $binario"
        install -m 0755 "$binario" "$destino" || die "falha ao instalar em $destino"
        # Symlink, e nao copia: as duas entradas nao podem divergir depois de um
        # upgrade feito por um dos dois nomes.
    fi

    if caminho_no_path "$base"; then
        log "  PATH         $base ja esta no PATH"
    else
        log "  PATH         ATENCAO: $base nao esta no PATH nesta sessao"
        log "               acrescente a linha abaixo ao seu ~/.bashrc ou ~/.zshrc:"
        log "               export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# ── Interface ───────────────────────────────────────────────────────────────

uso() {
    cat <<EOF
SmartSec $VERSAO_SCRIPTO - instalador sem privilegios de root

Uso: scripts/install.sh [OPCOES]

Opcoes:
  --dry-run        Mostra o que seria feito e nao escreve nada.
  --check          So checa os pre-requisitos de runtime.
  --build          Compila a partir do codigo em vez de usar o binario pronto.
  --bin <ARQUIVO>  Instala um binario ja compilado.
  --prefix <DIR>   Destino da instalacao (padrao: \$XDG_BIN_HOME ou ~/.local/bin).
  --self-test      Roda os testes da logica de deteccao.
  -h, --help       Esta ajuda.
  -V, --version    Versao do instalador.

Depois de instalado:
  $COMANDO --version
  $COMANDO scan --target https://exemplo.com

O binario sozinho nao basta: o runtime exige Podman rootless, o backend de
rede pasta e os templates do Nuclei. O script reporta o que falta.
EOF
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) MODO_DRY_RUN=1 ;;
            --check) MODO_SO_CHECAGEM=1 ;;
            --build) MODO_COMPILAR=1 ;;
            --self-test) MODO_TESTE=1 ;;
            --bin)
                [ $# -ge 2 ] || die "--bin exige um caminho"
                BINARIO_FONTE="$2"
                shift
                ;;
            --prefix)
                [ $# -ge 2 ] || die "--prefix exige um diretorio"
                PASTA_ALVO="$2"
                shift
                ;;
            -h | --help)
                uso
                return 0
                ;;
            -V | --version)
                printf 'install.sh %s\n' "$VERSAO_SCRIPTO"
                return 0
                ;;
            *) die "opcao desconhecida: $1 (use --help)" ;;
        esac
        shift
    done

    if [ "$MODO_TESTE" -eq 1 ]; then
        self_test
        return $?
    fi

    if [ "$(classificar_os "$(uname -s)")" = "macos" ]; then
        aviso "macOS e suporte experimental: o TCC valida Podman rootless no Linux."
        aviso "No macOS o Podman roda em uma maquina virtual e o isolamento nao e o mesmo."
    fi

    levantar_pre_requisitos

    if [ "$PRE_REQUISITOS_PENDENTES" -gt 0 ]; then
        explicar_pre_requisitos
        log ""
        aviso "$PRE_REQUISITOS_PENDENTES pre-requisito(s) pendente(s); o $COMANDO instala, mas o scan falha ate eles serem resolvidos."
    fi

    if [ "$MODO_SO_CHECAGEM" -eq 1 ]; then
        [ "$PRE_REQUISITOS_PENDENTES" -eq 0 ] || return 1
        log "Tudo pronto para varredura."
        return 0
    fi

    instalar
}

# As funcoes de classificacao sao puras de proposito: e o que permite testar a
# deteccao de SO, arquitetura e distro sem depender da maquina.
self_test() {
    local falhas=0

    afirmar_igual() {
        local esperado="$1" obtido="$2" rotulo="$3"
        if [ "$esperado" = "$obtido" ]; then
            printf 'ok   %s\n' "$rotulo"
        else
            printf 'FALHA %s: esperado %s, obtido %s\n' "$rotulo" "$esperado" "$obtido"
            falhas=$((falhas + 1))
        fi
    }

    afirmar_igual linux "$(classificar_os Linux)" 'classificar_os Linux'
    afirmar_igual macos "$(classificar_os Darwin)" 'classificar_os Darwin'
    afirmar_igual desconhecido "$(classificar_os MINGW64_NT-10.0)" 'classificar_os desconhecido'

    afirmar_igual x86_64 "$(classificar_arq x86_64)" 'classificar_arq x86_64'
    afirmar_igual aarch64 "$(classificar_arq aarch64)" 'classificar_arq aarch64'
    afirmar_igual desconhecido "$(classificar_arq riscv64)" 'classificar_arq desconhecido'

    afirmar_igual debian "$(classificar_distro ubuntu)" 'classificar_distro ubuntu'
    afirmar_igual rhel "$(classificar_distro fedora)" 'classificar_distro fedora'
    afirmar_igual arch "$(classificar_distro arch)" 'classificar_distro arch'
    afirmar_igual suse "$(classificar_distro opensuse-tumbleweed)" 'classificar_distro opensuse'
    afirmar_igual desconhecido "$(classificar_distro plan9)" 'classificar_distro desconhecido'

    local salvo_os_release
    salvo_os_release="${SMARTSEC_OS_RELEASE:-}"
    SMARTSEC_OS_RELEASE=/dev/null
    afirmar_igual desconhecido "$(detectar_id_distro)" 'detectar_id_distro sem os-release'
    afirmar_igual desconhecido "$(detectar_familia_distro)" 'detectar_familia_distro sem os-release'
    SMARTSEC_OS_RELEASE="$salvo_os_release"

    local fixture
    fixture="$(mktemp)"
    printf 'NAME=Omarchy\nID=omarchy\nID_LIKE=arch\n' >"$fixture"
    SMARTSEC_OS_RELEASE="$fixture"
    afirmar_igual omarchy "$(detectar_id_distro)" 'detectar_id_distro le ID'
    afirmar_igual arch "$(detectar_familia_distro)" 'detectar_familia_distro cai em ID_LIKE'
    rm -f "$fixture"
    SMARTSEC_OS_RELEASE="$salvo_os_release"

    if instrucoes_podman debian | grep -q 'apt-get install -y podman passt'; then
        printf 'ok   instrucoes_podman debian cita apt-get\n'
    else
        printf 'FALHA instrucoes_podman debian nao cita apt-get\n'
        falhas=$((falhas + 1))
    fi
    if instrucoes_podman arch | grep -q 'pacman -S podman passt'; then
        printf 'ok   instrucoes_podman arch cita pacman\n'
    else
        printf 'FALHA instrucoes_podman arch nao cita pacman\n'
        falhas=$((falhas + 1))
    fi
    if instrucoes_podman desconhecido | grep -qi 'podman'; then
        printf 'ok   instrucoes_podman desconhecido ainda orienta\n'
    else
        printf 'FALHA instrucoes_podman desconhecido ficou sem orientacao\n'
        falhas=$((falhas + 1))
    fi

    if caminho_no_path "/usr/bin"; then
        printf 'ok   caminho_no_path detecta diretorio presente\n'
    else
        printf 'FALHA caminho_no_path: /usr/bin deveria estar no PATH\n'
        falhas=$((falhas + 1))
    fi
    if caminho_no_path "/caminho/que/nao/existe"; then
        printf 'FALHA caminho_no_path nao deveria aceitar diretorio ausente\n'
        falhas=$((falhas + 1))
    else
        printf 'ok   caminho_no_path rejeita diretorio ausente\n'
    fi

    local salvo_xdg
    salvo_xdg="${XDG_BIN_HOME:-}"
    XDG_BIN_HOME=/tmp/prefixo-smartsec
    afirmar_igual /tmp/prefixo-smartsec "$(destino_bin)" 'destino_bin respeita XDG_BIN_HOME'
    XDG_BIN_HOME="$salvo_xdg"
    XDG_BIN_HOME=""
    afirmar_igual "$HOME/.local/bin" "$(destino_bin)" 'destino_bin assume ~/.local/bin'
    XDG_BIN_HOME="$salvo_xdg"

    PASTA_ALVO=/opt/binario
    afirmar_igual /opt/binario "$(destino_bin)" 'destino_bin respeita --prefix'
    PASTA_ALVO=""

    afirmar_igual "$HOME/nuclei-templates" "$(caminho_templates)" 'caminho_templates padrao'
    SMARTSEC_NUCLEI_TEMPLATES=/tmp/templates
    afirmar_igual /tmp/templates "$(caminho_templates)" 'caminho_templates respeita override'
    SMARTSEC_NUCLEI_TEMPLATES=""

    printf '\n'
    if [ "$falhas" -eq 0 ]; then
        printf 'self-test: todas as verificacoes passaram\n'
        return 0
    fi
    printf 'self-test: %d verificacao(oes) falharam\n' "$falhas"
    return 1
}

main "$@"
