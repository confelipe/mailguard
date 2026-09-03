#!/bin/bash
# Script de teste de envio de e-mail via MailGuard Relay
DESTINO="${1:-admin@example.com}"
HOST_RELAY="${2:-127.0.0.1}"
PORTA="${3:-25}"

echo "Enviando e-mail de teste para: ${DESTINO} via ${HOST_RELAY}:${PORTA}..."

nc "${HOST_RELAY}" "${PORTA}" <<EOF
EHLO mailguard.local
MAIL FROM:<notificacoes@example.com>
RCPT TO:<${DESTINO}>
DATA
From: "MailGuard Alertas" <notificacoes@example.com>
To: <${DESTINO}>
Subject: Teste de Envio - MailGuard SMTP Relay

Ola,

Este eh um e-mail de teste disparado atraves do MailGuard Relay no Kubernetes.
Entrega realizada com sucesso.

Atenciosamente,
Equipe MailGuard
.
QUIT
EOF

echo ""
echo "Comando concluído. Verifique os logs do MailGuard:"
echo "kubectl -n infraestrutura logs --tail=20 deployment/mailguard"
