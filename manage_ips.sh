#!/bin/bash
# ==============================================================================
# Script de Gerenciamento Dinâmico de IPs Permitidos - MailGuard
# ==============================================================================

NAMESPACE="infraestrutura"
CONFIGMAP="mailguard-allowed-ips"
DEPLOYMENT="mailguard"
DATA_KEY="allowed_ips.cidr"

# Cores para saída
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DEFAULT_CONTENT="# ==============================================================================
# Tabela de IPs / Redes Autorizadas para Relay no MailGuard
# Formato: <IP_OU_CIDR>    OK # <Descricao_Opcional>
# ==============================================================================

# Loopback & Redes Internas do Cluster
127.0.0.0/8            OK # Localhost
10.0.0.0/8             OK # Rede Interna do Cluster"

function show_help() {
    echo -e "${BLUE}Gerenciador de IPs Permitidos - MailGuard${NC}"
    echo "Uso: $0 [comando] [argumentos]"
    echo ""
    echo "Comandos disponíveis:"
    echo -e "  ${GREEN}list${NC}                           - Lista todos os IPs/Redes autorizados"
    echo -e "  ${GREEN}add <IP/CIDR> \"<Descricao>\"${NC}    - Adiciona um novo IP ou Sub-rede com descrição"
    echo -e "  ${GREEN}remove <IP/CIDR>${NC}               - Remove um IP ou Sub-rede da lista"
    echo -e "  ${GREEN}edit${NC}                           - Abre o ConfigMap no editor padrão (kubectl edit)"
    echo -e "  ${GREEN}reload${NC}                         - Força o recarregamento do Postfix no Pod"
    echo ""
    echo "Exemplos:"
    echo "  $0 list"
    echo "  $0 add 192.168.1.50/32 \"Servidor Grafana\""
    echo "  $0 add 192.168.10.0/24 \"Rede Servidores\""
    echo "  $0 remove 192.168.1.50/32"
    echo ""
}

function ensure_configmap() {
    if ! kubectl -n "${NAMESPACE}" get cm "${CONFIGMAP}" >/dev/null 2>&1; then
        echo -e "${YELLOW}Criando ConfigMap '${CONFIGMAP}' inicial no namespace '${NAMESPACE}'...${NC}"
        kubectl -n "${NAMESPACE}" create configmap "${CONFIGMAP}" \
            --from-literal="${DATA_KEY}=${DEFAULT_CONTENT}" >/dev/null
    else
        EXISTING=$(kubectl -n "${NAMESPACE}" get cm "${CONFIGMAP}" -o go-template='{{index .data "'"${DATA_KEY}"'"}}' 2>/dev/null)
        if [ -z "$EXISTING" ]; then
            kubectl -n "${NAMESPACE}" create configmap "${CONFIGMAP}" \
                --from-literal="${DATA_KEY}=${DEFAULT_CONTENT}" \
                --dry-run=client -o yaml | kubectl apply -f - >/dev/null
        fi
    fi
}

function get_current_list() {
    ensure_configmap
    kubectl -n "${NAMESPACE}" get cm "${CONFIGMAP}" -o go-template='{{index .data "'"${DATA_KEY}"'"}}' 2>/dev/null
}

function list_ips() {
    echo -e "${BLUE}=== Lista de IPs / Redes Autorizadas no MailGuard ===${NC}"
    CURRENT=$(get_current_list)
    echo "$CURRENT"
    echo ""
}

function add_ip() {
    IP_INPUT="$1"
    DESC="$2"

    if [ -z "$IP_INPUT" ]; then
        echo -e "${RED}Erro: Você deve informar o IP ou CIDR a ser adicionado.${NC}"
        echo "Exemplo: $0 add 192.168.1.50/32 \"Servidor Grafana\""
        exit 1
    fi

    if [[ ! "$IP_INPUT" =~ / ]]; then
        IP_INPUT="${IP_INPUT}/32"
    fi

    CURRENT=$(get_current_list)
    
    if echo "$CURRENT" | grep -E "^[[:space:]]*${IP_INPUT}[[:space:]]+" >/dev/null; then
        echo -e "${YELLOW}Aviso: O IP/Range '${IP_INPUT}' já está presente na lista!${NC}"
        exit 0
    fi

    NEW_ENTRY="${IP_INPUT}    OK"
    if [ -n "$DESC" ]; then
        NEW_ENTRY="${NEW_ENTRY} # ${DESC}"
    fi

    UPDATED="${CURRENT}"$'\n'"${NEW_ENTRY}"

    kubectl -n "${NAMESPACE}" create configmap "${CONFIGMAP}" \
        --from-literal="${DATA_KEY}=${UPDATED}" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null

    echo -e "${GREEN}✓ IP/Range '${IP_INPUT}' adicionado com sucesso!${NC}"
    reload_postfix
}

function remove_ip() {
    IP_INPUT="$1"

    if [ -z "$IP_INPUT" ]; then
        echo -e "${RED}Erro: Você deve informar o IP ou CIDR a ser removido.${NC}"
        exit 1
    fi

    if [[ ! "$IP_INPUT" =~ / ]]; then
        IP_INPUT="${IP_INPUT}/32"
    fi

    CURRENT=$(get_current_list)

    if ! echo "$CURRENT" | grep -E "^[[:space:]]*${IP_INPUT}[[:space:]]+" >/dev/null; then
        echo -e "${YELLOW}Aviso: O IP/Range '${IP_INPUT}' não foi encontrado na lista.${NC}"
        exit 0
    fi

    UPDATED=$(echo "$CURRENT" | grep -v -E "^[[:space:]]*${IP_INPUT}[[:space:]]+")

    kubectl -n "${NAMESPACE}" create configmap "${CONFIGMAP}" \
        --from-literal="${DATA_KEY}=${UPDATED}" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null

    echo -e "${GREEN}✓ IP/Range '${IP_INPUT}' removido com sucesso!${NC}"
    reload_postfix
}

function edit_configmap() {
    ensure_configmap
    echo -e "${BLUE}Abrindo ConfigMap ${CONFIGMAP} no editor...${NC}"
    kubectl -n "${NAMESPACE}" edit cm "${CONFIGMAP}"
    reload_postfix
}

function reload_postfix() {
    echo -e "${BLUE}Solicitando recarregamento de configuração ao Postfix...${NC}"
    kubectl -n "${NAMESPACE}" exec deployment/"${DEPLOYMENT}" -- postfix reload 2>/dev/null || true
    echo -e "${GREEN}✓ Postfix recarregado!${NC}"
}

case "$1" in
    list)
        list_ips
        ;;
    add)
        add_ip "$2" "$3"
        ;;
    remove|rm|del)
        remove_ip "$2"
        ;;
    edit)
        edit_configmap
        ;;
    reload)
        reload_postfix
        ;;
    *)
        show_help
        ;;
esac
