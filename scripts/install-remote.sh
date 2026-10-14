#!/bin/sh
# Bootstrap do SmartSec para `curl | sh`.
#
# Baixa o pacote da release (a mais recente, ou a de SMARTSEC_VERSION), confere
# o SHA256 contra o SHA256SUMS publicado e entrega a instalacao ao `install.sh`
# completo que vem dentro do pacote — que checa Podman rootless, o backend de
# rede `pasta` e os templates do Nuclei antes de deixar o primeiro scan falhar.
#
# Este arquivo roda em `sh` (dash no Debian/Ubuntu): nao use bashismos.

set -eu

VERSAO_SCRIPTO="1.0.0"
REPO="luis-ota/smartsec-rust"
BASE_URL="${SMARTSEC_BASE_URL:-https://github.com/$REPO/releases}"
VERSAO="${SMARTSEC_VERSION:-latest}"
PREFIXO="${SMARTSEC_INSTALL_DIR:-}"
SO_CHECAGEM=0
MANTER_TEMP=0
MODO_TESTE=0

# glibc do runner de release (Ubuntu 22.04). Distros mais antigas compilam do
# codigo; ver docs/INSTALACAO.md.
GLIBC_MINIMA="2.35"

log() { printf '%s\n' "$*"; }
aviso() { printf 'aviso: %s\n' "$*" >&2; }
erro() { printf 'erro: %s\n' "$*" >&2; }
die() {
    erro "$*"
    exit 1
}

# ── Funcoes puras (cobertas por --self-test) ────────────────────────────────

alvo_do_uname() {
    case "${1:-}/${2:-}" in
        Linux/x86_64 | Linux/amd64) printf 'x86_64-unknown-linux-gnu\n' ;;
        Linux/aarch64 | Linux/arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
        *) printf '\n' ;;
    esac
}

# Extrai `vX.Y.Z` da URL efetiva de /releases/latest (que redireciona para
# /releases/tag/vX.Y.Z).
tag_da_url_efetiva() {
    case "${1:-}" in
        */releases/tag/v*) printf '%s\n' "${1##*/releases/tag/}" ;;
        *) printf '\n' ;;
    esac
}

# Compara versoes "maior.menor" sem depender de `sort -V` (busybox nao tem).
versao_menor_que() {
    local_maior="${1%%.*}"
    local_menor="${1#*.}"
    local_menor="${local_menor%%.*}"
    minima_maior="${2%%.*}"
    minima_menor="${2#*.}"
    minima_menor="${minima_menor%%.*}"
    case "$local_maior$local_menor$minima_maior$minima_menor" in
        *[!0-9]*) return 1 ;;
    esac
    if [ "$local_maior" -lt "$minima_maior" ]; then
        return 0
    fi
    if [ "$local_maior" -gt "$minima_maior" ]; then
        return 1
    fi
    [ "$local_menor" -lt "$minima_menor" ]
}

# Le a linha do SHA256SUMS cujo nome de arquivo (sem o `./` inicial) casa.
soma_esperada() {
    awk -v alvo="${2:-}" '{ nome = $2; sub(/^\.\//, "", nome); if (nome == alvo) { print $1; exit } }' "${1:-/dev/null}"
}

# ── Rede e instalacao ───────────────────────────────────────────────────────

opcoes_tls() {
    case "$BASE_URL" in
        https://*) printf '%s\n' "--proto =https --tlsv1.2" ;;
        *) printf '\n' ;;
    esac
}

baixar() {
    # shellcheck disable=SC2086
    curl -fsSL --retry 3 $(opcoes_tls) -o "$2" "$1" ||
        die "falha ao baixar $1 (rede ou tag inexistente)"
}

resolver_tag() {
    url_efetiva="$(curl -fsSL --retry 3 $(opcoes_tls) -o /dev/null -w '%{url_effective}' "$BASE_URL/latest")" ||
        die "nao consegui resolver a versao mais recente em $BASE_URL/latest"
    tag="$(tag_da_url_efetiva "$url_efetiva")"
    [ -n "$tag" ] || die "resposta inesperada de $BASE_URL/latest: $url_efetiva"
    printf '%s\n' "$tag"
}

verificar_sha256() {
    arquivo="$1"
    somas="$2"
    nome="$3"
    esperada="$(soma_esperada "$somas" "$nome")"
    [ -n "$esperada" ] || die "o SHA256SUMS publicado nao tem entrada para $nome"
    if command -v sha256sum >/dev/null 2>&1; then
        obtida="$(sha256sum "$arquivo" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        obtida="$(shasum -a 256 "$arquivo" | awk '{print $1}')"
    else
        die "sem sha256sum nem shasum para conferir o download"
    fi
    [ "$obtida" = "$esperada" ] ||
        die "SHA256 nao confere para $nome (esperado $esperada, obtido $obtida)"
    log "  checksum     ok"
}

verificar_glibc() {
    case "${1:-}" in
        *-gnu) ;;
        *) return 0 ;;
    esac
    atual="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')" || return 0
    [ -n "$atual" ] || return 0
    if versao_menor_que "$atual" "$GLIBC_MINIMA"; then
        die "este pacote exige glibc >= $GLIBC_MINIMA (encontrada $atual); compile do codigo (docs/INSTALACAO.md)"
    fi
}

uso() {
    cat <<EOF
SmartSec $VERSAO_SCRIPTO - bootstrap do pacote de release

Uso recomendado:
  curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | sh

Variaveis de ambiente:
  SMARTSEC_VERSION      fixa a versao (ex.: v0.2.0); padrao: a mais recente
  SMARTSEC_INSTALL_DIR  destino do binario; padrao: ~/.local/bin
  SMARTSEC_BASE_URL     outra origem de release (testes locais)
  SMARTSEC_KEEP_TEMP=1  preserva a pasta temporaria do download

Opcoes (use `sh -s -- <opcao>` com curl):
  --check              so verifica os pre-requisitos de runtime, sem instalar
  --prefix <DIR>       mesmo efeito de SMARTSEC_INSTALL_DIR
  --self-test          testa a logica de deteccao do proprio script
  -h, --help           esta ajuda
  -V, --version        versao do bootstrap

O download e conferido contra o SHA256SUMS da release. Para inspecionar antes
de executar: baixe este arquivo, leia e rode `sh install.sh`.
EOF
}

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --check) SO_CHECAGEM=1 ;;
            --prefix)
                [ $# -ge 2 ] || die "--prefix exige um diretorio"
                PREFIXO="$2"
                shift
                ;;
            --self-test) MODO_TESTE=1 ;;
            -h | --help)
                uso
                return 0
                ;;
            -V | --version)
                printf 'install-remote.sh %s\n' "$VERSAO_SCRIPTO"
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

    command -v curl >/dev/null 2>&1 || die "curl e necessario para baixar o pacote"
    command -v tar >/dev/null 2>&1 || die "tar e necessario para extrair o pacote"

    alvo="$(alvo_do_uname "$(uname -s)" "$(uname -m)")"
    if [ -z "$alvo" ]; then
        die "sem pacote pronto para $(uname -s)/$(uname -m); compile do codigo (docs/INSTALACAO.md)"
    fi

    tag="$VERSAO"
    if [ "$VERSAO" = "latest" ]; then
        log "Resolvendo a versao mais recente em $BASE_URL/latest"
        tag="$(resolver_tag)"
    fi
    pacote="smartsec-${tag#v}-$alvo.tar.gz"

    work="$(mktemp -d "${TMPDIR:-/tmp}/smartsec.XXXXXX")" ||
        die "nao foi possivel criar a pasta temporaria"
    if [ "$MANTER_TEMP" -eq 1 ]; then
        trap 'aviso "pasta temporaria preservada em $work"' EXIT
    else
        trap 'rm -rf "$work"' EXIT INT TERM
    fi

    log "SmartSec $tag ($alvo)"
    log "  baixando     $pacote"
    baixar "$BASE_URL/download/$tag/$pacote" "$work/$pacote"
    baixar "$BASE_URL/download/$tag/SHA256SUMS" "$work/SHA256SUMS"
    verificar_sha256 "$work/$pacote" "$work/SHA256SUMS" "$pacote"
    verificar_glibc "$alvo"

    tar -xzf "$work/$pacote" -C "$work" || die "pacote corrompido: $pacote"
    [ -x "$work/smartsec" ] || die "o pacote nao trouxe o binario smartsec"
    [ -f "$work/install.sh" ] || die "o pacote nao trouxe o install.sh"

    if ! command -v bash >/dev/null 2>&1; then
        aviso "bash nao encontrado: instalando o binario sem a checagem de pre-requisitos"
        destino="${PREFIXO:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
        mkdir -p "$destino" || die "nao foi possivel criar $destino"
        install -m 0755 "$work/smartsec" "$destino/smartsec" ||
            die "nao foi possivel instalar em $destino"
        log "  instalado    $destino/smartsec"
        return 0
    fi

    set -- --bin "$work/smartsec"
    if [ -n "$PREFIXO" ]; then
        set -- "$@" --prefix "$PREFIXO"
    fi
    if [ "$SO_CHECAGEM" -eq 1 ]; then
        set -- "$@" --check
    fi
    log ""
    bash "$work/install.sh" "$@"
}

self_test() {
    falhas=0
    afirmar_igual() {
        if [ "$1" = "$2" ]; then
            printf 'ok   %s\n' "$3"
        else
            printf 'FALHA %s: esperado %s, obtido %s\n' "$3" "$1" "$2"
            falhas=$((falhas + 1))
        fi
    }

    afirmar_igual x86_64-unknown-linux-gnu "$(alvo_do_uname Linux x86_64)" 'alvo Linux x86_64'
    afirmar_igual x86_64-unknown-linux-gnu "$(alvo_do_uname Linux amd64)" 'alvo Linux amd64'
    afirmar_igual aarch64-unknown-linux-gnu "$(alvo_do_uname Linux aarch64)" 'alvo Linux aarch64'
    afirmar_igual '' "$(alvo_do_uname Darwin arm64)" 'alvo Darwin fica vazio'
    afirmar_igual '' "$(alvo_do_uname Linux riscv64)" 'alvo riscv64 fica vazio'

    afirmar_igual v0.2.0 "$(tag_da_url_efetiva 'https://github.com/luis-ota/smartsec-rust/releases/tag/v0.2.0')" 'tag da url efetiva'
    afirmar_igual '' "$(tag_da_url_efetiva 'https://github.com/luis-ota/smartsec-rust/releases')" 'url sem tag fica vazia'

    if versao_menor_que "2.31" "2.35"; then
        printf 'ok   versao_menor_que detecta 2.31 < 2.35\n'
    else
        printf 'FALHA versao_menor_que nao detectou 2.31 < 2.35\n'
        falhas=$((falhas + 1))
    fi
    if versao_menor_que "2.35" "2.35"; then
        printf 'FALHA versao_menor_que aceitou 2.35 < 2.35\n'
        falhas=$((falhas + 1))
    else
        printf 'ok   versao_menor_que aceita igual\n'
    fi
    if versao_menor_que "2.39" "2.35"; then
        printf 'FALHA versao_menor_que inverteu 2.39 < 2.35\n'
        falhas=$((falhas + 1))
    else
        printf 'ok   versao_menor_que rejeita maior\n'
    fi

    somas="$(mktemp)"
    arquivo="$(mktemp)"
    printf 'conteudo' >"$arquivo"
    printf 'aaaa  ./outro.tar.gz\nbbbb  smartsec-0.2.0-x86_64-unknown-linux-gnu.tar.gz\n' >"$somas"
    afirmar_igual bbbb "$(soma_esperada "$somas" smartsec-0.2.0-x86_64-unknown-linux-gnu.tar.gz)" 'soma_esperada acha a entrada'
    afirmar_igual '' "$(soma_esperada "$somas" inexistente.tar.gz)" 'soma_esperada devolve vazio para ausente'
    rm -f "$somas" "$arquivo"

    printf '\n'
    if [ "$falhas" -eq 0 ]; then
        printf 'self-test: todas as verificacoes passaram\n'
        return 0
    fi
    printf 'self-test: %d verificacao(oes) falharam\n' "$falhas"
    return 1
}

main "$@"
