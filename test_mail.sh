#!/usr/bin/env bash
# ==============================================================================
# Script de Teste de Envio de E-mail via MailGuard Relay
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Cores para saída no terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Carrega .env caso exista
if [ -f "${ENV_FILE}" ]; then
    set -a
    source "${ENV_FILE}" 2>/dev/null || true
    set +a
fi

# Parâmetros
DEFAULT_HOST="${MYHOSTNAME:-mailguard.local}"
DEFAULT_FROM="notificacoes@example.com"
if [ -n "$MYHOSTNAME" ] && [ "$MYHOSTNAME" != "mailguard.local" ]; then
    # Extrai o domínio principal para o remetente padrão
    DOMAIN="${MYHOSTNAME#*.}"
    DEFAULT_FROM="notificacoes@${DOMAIN}"
fi

DESTINO="${1:-carlos-f-silva@openlabs.com.br}"
REMETENTE="${2:-$DEFAULT_FROM}"
HOST_RELAY="${3:-$DEFAULT_HOST}"
PORTA="${4:-25}"

echo -e "${BLUE}=== Disparo de Teste de E-mail - MailGuard ===${NC}"
echo -e "Destinatário:  ${GREEN}${DESTINO}${NC}"
echo -e "Remetente:     ${GREEN}${REMETENTE}${NC}"
echo -e "Servidor SMTP: ${GREEN}${HOST_RELAY}:${PORTA}${NC}"
echo ""

# Disparo via Python smtplib nativo com diagnóstico detalhado
python3 -c "
import sys
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate

dest = '${DESTINO}'
sender = '${REMETENTE}'
host = '${HOST_RELAY}'
port = int('${PORTA}')

msg = MIMEText('Olá,\n\nEste é um e-mail de teste disparado com sucesso via MailGuard SMTP Relay.\nEntrega realizada e auditada.\n\nAtenciosamente,\nEquipe MailGuard\n', 'plain', 'utf-8')
msg['Subject'] = 'Teste de Envio - MailGuard SMTP Relay'
msg['From'] = f'MailGuard Alertas <{sender}>'
msg['To'] = dest
msg['Date'] = formatdate(localtime=True)

try:
    print(f'Conectando a {host}:{port}...')
    with smtplib.SMTP(host, port, timeout=10) as server:
        # Tenta STARTTLS se o servidor oferecer
        try:
            if server.has_extn('STARTTLS'):
                server.starttls()
        except Exception:
            pass
        
        # Envia e-mail
        res = server.sendmail(sender, [dest], msg.as_string())
        print('\033[0;32m✓ SUCESSO: E-mail aceito pelo MailGuard e enfileirado para entrega!\033[0m')
        print(f'Destino confirmado: {dest}')
except smtplib.SMTPRecipientsRefused as e:
    print(f'\033[0;31m✗ ERRO: Destinatário recusado pelo servidor: {e}\033[0m')
    sys.exit(1)
except smtplib.SMTPSenderRefused as e:
    print(f'\033[0;31m✗ ERRO: Remetente recusado pelo servidor: {e}\033[0m')
    sys.exit(1)
except smtplib.SMTPDataError as e:
    print(f'\033[0;31m✗ ERRO de dados no servidor SMTP: {e}\033[0m')
    sys.exit(1)
except smtplib.SMTPConnectError as e:
    print(f'\033[0;31m✗ ERRO de conexão SMTP com {host}:{port}: {e}\033[0m')
    sys.exit(1)
except Exception as e:
    print(f'\033[0;31m✗ FALHA NO DISPARO: {e}\033[0m')
    print('Verifique se o seu IP está cadastrado na Whitelist do MailGuard.')
    sys.exit(1)
"

EXIT_CODE=$?
echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Verifique a entrega nos logs do MailGuard ou no seu leitor de e-mails!${NC}"
else
    echo -e "${RED}O disparo falhou. Verifique os logs do MailGuard para mais detalhes.${NC}"
fi
exit $EXIT_CODE
