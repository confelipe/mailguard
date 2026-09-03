#!/bin/bash
# ==============================================================================
# Script de Automação de Build e Deploy do MailGuard
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

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

echo -e "${BLUE}=== Carregando variáveis do .env ===${NC}"
set -a
source "${ENV_FILE}"
set +a

# Valores padrão de segurança
NAMESPACE="${NAMESPACE:-infraestrutura}"
IMAGE_TAG="${IMAGE_TAG:-mailguard:3.4}"
CLUSTER_ISSUER="${CLUSTER_ISSUER:-cluster-ca-issuer}"
MYHOSTNAME="${MYHOSTNAME:-mailguard.local}"
SMTP_RELAY_HOST="${SMTP_RELAY_HOST:-[smtp.office365.com]:25}"
TZ="${TZ:-America/Sao_Paulo}"
GRAYLOG_HOST="${GRAYLOG_HOST:-graylog.local}"
GRAYLOG_PORT="${GRAYLOG_PORT:-514}"
WAZUH_HOST="${WAZUH_HOST:-wazuh.local}"
WAZUH_PORT="${WAZUH_PORT:-1514}"
DASHBOARD_PORT="${DASHBOARD_PORT:-443}"
DASHBOARD_USER="${DASHBOARD_USER:-admin}"
DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-Admin@2026}"

echo -e "Namespace:       ${GREEN}${NAMESPACE}${NC}"
echo -e "Hostname:        ${GREEN}${MYHOSTNAME}${NC}"
echo -e "Relay Host:      ${GREEN}${SMTP_RELAY_HOST}${NC}"
echo -e "Dashboard:       ${GREEN}https://${MYHOSTNAME}:${DASHBOARD_PORT}${NC}"
echo -e "Imagem Docker:   ${GREEN}${IMAGE_TAG}${NC}"
echo -e "ClusterIssuer:   ${GREEN}${CLUSTER_ISSUER}${NC}"
echo ""

# 1. Build da Imagem
echo -e "${BLUE}1/3. Construindo imagem Docker...${NC}"
docker build -t "${IMAGE_TAG}" "${SCRIPT_DIR}"

# 2. Push da Imagem
echo -e "${BLUE}2/3. Enviando imagem para o Registry...${NC}"
docker push "${IMAGE_TAG}"

# 3. Aplicar no Kubernetes
echo -e "${BLUE}3/3. Aplicando manifestos no Kubernetes (${NAMESPACE})...${NC}"
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Renderizar manifesto temporário com as variáveis do .env
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mailguard-sa
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mailguard-configmap-role
  namespace: ${NAMESPACE}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["mailguard-allowed-ips"]
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: mailguard-configmap-rb
  namespace: ${NAMESPACE}
subjects:
  - kind: ServiceAccount
    name: mailguard-sa
    namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: mailguard-configmap-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tls-mailguard
  namespace: ${NAMESPACE}
spec:
  secretName: tls-mailguard
  commonName: ${MYHOSTNAME}
  subject:
    organizations:
      - Infrastructure
    organizationalUnits:
      - K8S
    countries:
      - BR
  dnsNames:
    - ${MYHOSTNAME}
    - mailguard
    - mailguard.${NAMESPACE}
    - mailguard.${NAMESPACE}.svc.cluster.local
  issuerRef:
    kind: ClusterIssuer
    name: ${CLUSTER_ISSUER}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mailguard-config
  namespace: ${NAMESPACE}
data:
  TZ: "${TZ}"
  MYHOSTNAME: "${MYHOSTNAME}"
  SMTP_RELAY_HOST: "${SMTP_RELAY_HOST}"
  GRAYLOG_HOST: "${GRAYLOG_HOST}"
  GRAYLOG_PORT: "${GRAYLOG_PORT}"
  WAZUH_HOST: "${WAZUH_HOST}"
  WAZUH_PORT: "${WAZUH_PORT}"
  DASHBOARD_PORT: "${DASHBOARD_PORT}"
  DASHBOARD_USER: "${DASHBOARD_USER}"
  DASHBOARD_PASSWORD: "${DASHBOARD_PASSWORD}"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mailguard-allowed-ips
  namespace: ${NAMESPACE}
data:
  allowed_ips.cidr: |
    # ==============================================================================
    # Tabela de IPs / Redes Autorizadas para Relay no MailGuard
    # Formato: <IP_OU_CIDR>    OK # <Descricao_Opcional>
    # ==============================================================================

    # Loopback & Redes Internas do Cluster
    127.0.0.0/8            OK # Localhost
    10.0.0.0/8             OK # Rede Interna do Cluster
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mailguard
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mailguard
  template:
    metadata:
      labels:
        app: mailguard
    spec:
      serviceAccountName: mailguard-sa
      containers:
        - name: mailguard
          image: ${IMAGE_TAG}
          imagePullPolicy: Always
          resources:
            limits:
              cpu: 350m
              memory: 384Mi
            requests:
              cpu: 50m
              memory: 64Mi
          ports:
            - name: smtp
              containerPort: 25
            - name: submission
              containerPort: 587
            - name: https
              containerPort: 443
          envFrom:
            - configMapRef:
                name: mailguard-config
          volumeMounts:
            - name: tls-cert
              mountPath: /etc/ssl/mailguard
              readOnly: true
            - name: allowed-ips
              mountPath: /etc/mailguard/configmap
              readOnly: true
          livenessProbe:
            exec:
              command:
                - /bin/sh
                - -c
                - "kill -0 1"
            initialDelaySeconds: 15
            periodSeconds: 20
          readinessProbe:
            exec:
              command:
                - /bin/sh
                - -c
                - "kill -0 1"
            initialDelaySeconds: 10
            periodSeconds: 15
      volumes:
        - name: tls-cert
          secret:
            secretName: tls-mailguard
            defaultMode: 0400
            optional: true
        - name: allowed-ips
          configMap:
            name: mailguard-allowed-ips
            defaultMode: 0400
            optional: true
---
apiVersion: v1
kind: Service
metadata:
  name: mailguard
  namespace: ${NAMESPACE}
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  selector:
    app: mailguard
  ports:
    - name: smtp
      protocol: TCP
      port: 25
      targetPort: 25
    - name: submission
      protocol: TCP
      port: 587
      targetPort: 587
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443
EOF

echo ""
echo -e "${GREEN}✓ Deploy concluído com sucesso!${NC}"
echo "Verifique o status do serviço:"
echo "kubectl -n ${NAMESPACE} get svc mailguard"
