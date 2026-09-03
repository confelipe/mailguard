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

# Habilitar Serviço Submission (Porta 587) no master.cf
postconf -M submission/inet="submission inet n - n - - smtpd"
postconf -P "submission/inet/syslog_name=postfix/submission"
postconf -P "submission/inet/smtpd_tls_security_level=may"
postconf -P "submission/inet/smtpd_sasl_auth_enable=no"

# Inicialização do Arquivo de IPs Gravável
mkdir -p /etc/mailguard
WORK_CIDR="/etc/mailguard/allowed_ips.cidr"
CM_MOUNT=""

if [ -f "/etc/mailguard/configmap/allowed_ips.cidr" ]; then
    CM_MOUNT="/etc/mailguard/configmap/allowed_ips.cidr"
elif [ -f "/etc/mailguard/rules/allowed_ips.cidr" ]; then
    CM_MOUNT="/etc/mailguard/rules/allowed_ips.cidr"
fi

if [ -n "${CM_MOUNT}" ]; then
    echo "Copiando regras do ConfigMap (${CM_MOUNT}) para o arquivo de trabalho gravável..."
    cp -f "${CM_MOUNT}" "${WORK_CIDR}"
elif [ ! -f "${WORK_CIDR}" ]; then
    echo "Criando arquivo de regras padrão..."
    cat <<EOF > "${WORK_CIDR}"
# ==============================================================================
# Tabela de IPs / Redes Autorizadas para Relay no MailGuard
# ==============================================================================
127.0.0.0/8            OK # Localhost
10.0.0.0/8             OK # Rede Interna do Cluster
EOF
fi

chmod 666 "${WORK_CIDR}" 2>/dev/null || true

echo "Carregando tabela CIDR de IPs permitidos (${WORK_CIDR})..."
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128 cidr:${WORK_CIDR}"

# Conector de Saída / Relay Host
if [ -n "$SMTP_RELAY_HOST" ]; then
    postconf -e "relayhost = ${SMTP_RELAY_HOST}"
else
    postconf -e "relayhost = [smtp.office365.com]:25"
fi

# Sem autenticação SASL no cliente SMTP
postconf -e "smtp_sasl_auth_enable = no"

# TLS de Saída
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_tls_security_level = encrypt"
postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
postconf -e "smtp_tls_session_cache_database = lmdb:/var/lib/postfix/smtp_scache"

# TLS de Entrada (Servidor)
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

# Watchdog para sincronizar alterações do ConfigMap com o arquivo de trabalho gravável
if [ -n "${CM_MOUNT}" ]; then
    (
        LAST_MOD=$(stat -c %Y "${CM_MOUNT}" 2>/dev/null || echo 0)
        while true; do
            sleep 5
            CURRENT_MOD=$(stat -c %Y "${CM_MOUNT}" 2>/dev/null || echo 0)
            if [ "$CURRENT_MOD" != "$LAST_MOD" ] && [ "$CURRENT_MOD" != "0" ]; then
                echo "[Watchdog] Alteração detectada no ConfigMap (${CM_MOUNT}). Sincronizando com arquivo de trabalho..."
                cp -f "${CM_MOUNT}" "${WORK_CIDR}"
                chmod 666 "${WORK_CIDR}" 2>/dev/null || true
                postfix reload 2>/dev/null || true
                LAST_MOD="$CURRENT_MOD"
            fi
        done
    ) &
fi

# Verificação de sintaxe e inicialização em primeiro plano
postfix check
exec postfix start-fg
