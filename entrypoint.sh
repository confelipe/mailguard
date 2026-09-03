#!/bin/bash
set -e

# Configuração de Fuso Horário
if [ -n "$TZ" ]; then
    cp /usr/share/zoneinfo/${TZ} /etc/localtime
    echo "${TZ}" > /etc/timezone
fi

# Garantir banco de aliases compilado
touch /etc/aliases /etc/postfix/aliases 2>/dev/null || true
newaliases 2>/dev/null || true

# Hostname e Identificação
postconf -e "myhostname = ${MYHOSTNAME:-mailguard.local}"
postconf -e "mydestination = localhost"

# Hardening de Segurança no Postfix
postconf -e "smtpd_banner = \$myhostname ESMTP MailGuard"
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_helo_required = yes"
postconf -e "smtpd_client_connection_count_limit = 50"
postconf -e "smtpd_client_connection_rate_limit = 120"
postconf -e "smtpd_client_message_rate_limit = 300"
postconf -e "message_size_limit = 36700160"

# Configuração de Redes Confiáveis (Tabela CIDR ou Variável)
CIDR_RULES="/etc/mailguard/rules/allowed_ips.cidr"
if [ -f "${CIDR_RULES}" ]; then
    echo "Carregando tabela CIDR de IPs permitidos (${CIDR_RULES})..."
    postconf -e "mynetworks = 127.0.0.0/8 [::1]/128 cidr:${CIDR_RULES}"
else
    echo "Tabela CIDR não encontrada. Usando MYNETWORKS padrão..."
    postconf -e "mynetworks = ${MYNETWORKS:-127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
fi

# Conector de Saída / Relay Host
if [ -n "$SMTP_RELAY_HOST" ]; then
    postconf -e "relayhost = ${SMTP_RELAY_HOST}"
else
    postconf -e "relayhost = [smtp.office365.com]:25"
fi

# Sem autenticação SASL
postconf -e "smtp_sasl_auth_enable = no"

# TLS de Saída
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
postconf -e "smtp_tls_session_cache_database = lmdb:/var/lib/postfix/smtp_scache"

# TLS de Entrada
SSL_DIR="/etc/ssl/mailguard"
if [ -f "${SSL_DIR}/tls.crt" ] && [ -f "${SSL_DIR}/tls.key" ]; then
    echo "Configurando certificado TLS de servidor (${SSL_DIR}/tls.crt)..."
    postconf -e "smtpd_tls_cert_file = ${SSL_DIR}/tls.crt"
    postconf -e "smtpd_tls_key_file = ${SSL_DIR}/tls.key"
    postconf -e "smtpd_tls_security_level = may"
    postconf -e "smtpd_tls_protocols = >=TLSv1.2"
    postconf -e "smtpd_tls_loglevel = 1"
    postconf -e "smtpd_tls_session_cache_database = lmdb:/var/lib/postfix/smtpd_scache"
fi

# Preservação de Cabeçalhos e Remetentes
postconf -e "always_add_missing_headers = yes"

# Configuração de Gravação de Log do Postfix em /var/log/mail.log
mkdir -p /var/log
touch /var/log/mail.log
chmod 666 /var/log/mail.log
postconf -e "maillog_file = /var/log/mail.log"

# Iniciar o Log Forwarder (Graylog, Wazuh e Console)
python3 -u /log_forwarder.py &

# Iniciar o MailGuard Web Dashboard (:443 / HTTPS)
python3 -u /dashboard.py &

# Watchdog em background para recarga automática quando o ConfigMap mudar
if [ -f "${CIDR_RULES}" ]; then
    (
        LAST_MOD=$(stat -c %Y "${CIDR_RULES}" 2>/dev/null || echo 0)
        while true; do
            sleep 5
            CURRENT_MOD=$(stat -c %Y "${CIDR_RULES}" 2>/dev/null || echo 0)
            if [ "$CURRENT_MOD" != "$LAST_MOD" ] && [ "$CURRENT_MOD" != "0" ]; then
                echo "[Watchdog] Alteração detectada em ${CIDR_RULES}. Recarregando Postfix..."
                postfix reload 2>/dev/null || true
                LAST_MOD="$CURRENT_MOD"
            fi
        done
    ) &
fi

# Verificação de sintaxe e inicialização em primeiro plano
postfix check
exec postfix start-fg
