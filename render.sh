#!/bin/bash
# ==============================================================================
# Script para Renderizar o Manifesto mailguard.yaml a partir do .env
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
TEMPLATE_FILE="${SCRIPT_DIR}/mailguard.template.yaml"
OUTPUT_FILE="${SCRIPT_DIR}/mailguard.yaml"

# Cores para saída
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}Erro: Arquivo .env não encontrado!${NC}"
    echo "Crie o arquivo .env a partir do template:"
    echo "cp .env.example .env"
    exit 1
fi

echo -e "${BLUE}=== Renderizando mailguard.yaml a partir do .env ===${NC}"
set -a
source "${ENV_FILE}"
set +a

# Valores padrão caso não definidos no .env
NAMESPACE="${NAMESPACE:-infraestrutura}"
IMAGE_TAG="${IMAGE_TAG:-harbor.k8s.openlabs.local/library/mailguard:3.4}"
CLUSTER_ISSUER="${CLUSTER_ISSUER:-kubernets-ca-openlabs}"
MYHOSTNAME="${MYHOSTNAME:-mailguard.openlabs.interno}"
SMTP_RELAY_HOST="${SMTP_RELAY_HOST:-[openlabs-com-br.mail.protection.outlook.com]:25}"
TZ="${TZ:-America/Sao_Paulo}"
GRAYLOG_HOST="${GRAYLOG_HOST:-graylog.openlabs.interno}"
GRAYLOG_PORT="${GRAYLOG_PORT:-514}"
WAZUH_HOST="${WAZUH_HOST:-wazuh.openlabs.interno}"
WAZUH_PORT="${WAZUH_PORT:-1514}"
DASHBOARD_PORT="${DASHBOARD_PORT:-443}"
DASHBOARD_USER="${DASHBOARD_USER:-admin}"
DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-Openlabs@2026}"

# Substituição de variáveis via Python para máxima compatibilidade
python3 -c "
import os
import string

template_path = '${TEMPLATE_FILE}'
output_path = '${OUTPUT_FILE}'

with open(template_path, 'r', encoding='utf-8') as f:
    content = f.read()

mapping = {
    'NAMESPACE': '${NAMESPACE}',
    'IMAGE_TAG': '${IMAGE_TAG}',
    'CLUSTER_ISSUER': '${CLUSTER_ISSUER}',
    'MYHOSTNAME': '${MYHOSTNAME}',
    'SMTP_RELAY_HOST': '${SMTP_RELAY_HOST}',
    'TZ': '${TZ}',
    'GRAYLOG_HOST': '${GRAYLOG_HOST}',
    'GRAYLOG_PORT': '${GRAYLOG_PORT}',
    'WAZUH_HOST': '${WAZUH_HOST}',
    'WAZUH_PORT': '${WAZUH_PORT}',
    'DASHBOARD_PORT': '${DASHBOARD_PORT}',
    'DASHBOARD_USER': '${DASHBOARD_USER}',
    'DASHBOARD_PASSWORD': '${DASHBOARD_PASSWORD}'
}

template = string.Template(content)
rendered = template.safe_substitute(mapping)

with open(output_path, 'w', encoding='utf-8') as f:
    f.write(rendered)

print('Arquivo mailguard.yaml gerado com sucesso!')
"

echo -e "${GREEN}✓ Manifesto local gerado: ${OUTPUT_FILE}${NC}"
echo -e "  - Hostname:       ${GREEN}${MYHOSTNAME}${NC}"
echo -e "  - Imagem Docker:  ${GREEN}${IMAGE_TAG}${NC}"
echo -e "  - Relay:          ${GREEN}${SMTP_RELAY_HOST}${NC}"
echo -e "  - ClusterIssuer:  ${GREEN}${CLUSTER_ISSUER}${NC}"
echo ""
echo -e "Para aplicar no Kubernetes, execute:"
echo -e "  ${YELLOW}kubectl apply -f mailguard.yaml${NC}"
