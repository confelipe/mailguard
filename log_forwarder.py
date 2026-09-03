#!/usr/bin/env python3
import os
import sys
import re
import time
import socket
from collections import OrderedDict

LOG_FILE = "/var/log/mail.log"
GRAYLOG_HOST = os.environ.get("GRAYLOG_HOST", "graylog.local")
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_PORT", "514"))
WAZUH_HOST = os.environ.get("WAZUH_HOST", "wazuh.local")
WAZUH_PORT = int(os.environ.get("WAZUH_PORT", "1514"))
MYHOSTNAME = os.environ.get("MYHOSTNAME", "mailguard.local")

NOISE_PATTERNS = [
    "commands=0/0",
    "lost connection after CONNECT",
    "the Postfix mail system is running",
    "improper command pipelining after CONNECT",
    "connect from 10-",
    "connect from 172-",
    "connect from 192-",
]

# Regexes para captura e correlação de eventos
RE_CLIENT = re.compile(r'postfix/smtpd\[\d+\]:\s+([A-Za-z0-9]+):\s+client=([^\[]+)\[([0-9a-fA-F\.:]+)\]')
RE_FROM = re.compile(r'postfix/qmgr\[\d+\]:\s+([A-Za-z0-9]+):\s+from=<([^>]*)>,\s+size=(\d+)')
RE_TO = re.compile(r'postfix/smtp\[\d+\]:\s+([A-Za-z0-9]+):\s+to=<([^>]*)>,\s+relay=([^,]+),\s+delay=[^,]+,\s+delays=[^,]+,\s+dsn=[^,]+,\s+status=([a-zA-Z]+)\s+\((.+)\)')
RE_REMOVED = re.compile(r'postfix/qmgr\[\d+\]:\s+([A-Za-z0-9]+):\s+removed')

# Dicionário limitado para rastreamento de transações em andamento
MAX_TRACKED = 500
TRANSACTIONS = OrderedDict()

def is_noise(line):
    for pattern in NOISE_PATTERNS:
        if pattern in line:
            return True
    return False

def log_msg(msg):
    print(f"[LogForwarder] {msg}", flush=True)

def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except Exception as e:
        log_msg(f"Erro ao resolver DNS de '{host}': {e}")
        return None

def process_transaction_correlation(clean_line, udp_sock, graylog_target, wazuh_target):
    """
    Correlaciona linhas do Postfix por Queue ID e emite um evento estruturado [MAIL_TRANSACTION].
    """
    # 1. Captura conexão de cliente (Origem)
    m_client = RE_CLIENT.search(clean_line)
    if m_client:
        qid, client_name, client_ip = m_client.groups()
        if qid not in TRANSACTIONS:
            if len(TRANSACTIONS) >= MAX_TRACKED:
                TRANSACTIONS.popitem(last=False)
            TRANSACTIONS[qid] = {
                "created_at": time.time(),
                "client_name": client_name.strip(),
                "client_ip": client_ip.strip(),
                "from": "",
                "size": 0,
                "recipients": []
            }
        else:
            TRANSACTIONS[qid]["client_name"] = client_name.strip()
            TRANSACTIONS[qid]["client_ip"] = client_ip.strip()
        return

    # 2. Captura Remetente (From)
    m_from = RE_FROM.search(clean_line)
    if m_from:
        qid, mail_from, mail_size = m_from.groups()
        if qid not in TRANSACTIONS:
            if len(TRANSACTIONS) >= MAX_TRACKED:
                TRANSACTIONS.popitem(last=False)
            TRANSACTIONS[qid] = {
                "created_at": time.time(),
                "client_name": "unknown",
                "client_ip": "127.0.0.1",
                "from": mail_from.strip(),
                "size": int(mail_size),
                "recipients": []
            }
        else:
            TRANSACTIONS[qid]["from"] = mail_from.strip()
            TRANSACTIONS[qid]["size"] = int(mail_size)
        return

    # 3. Captura Destinatário & Entrega (To & Status)
    m_to = RE_TO.search(clean_line)
    if m_to:
        qid, mail_to, relay, status, response = m_to.groups()
        t = TRANSACTIONS.get(qid, {
            "client_name": "unknown",
            "client_ip": "unknown",
            "from": "unknown",
            "size": 0
        })

        client_ip = t.get("client_ip", "unknown")
        client_name = t.get("client_name", "unknown")
        mail_from = t.get("from", "unknown")
        mail_size = t.get("size", 0)

        # Formata linha de auditoria estruturada
        now_str = time.strftime("%b %d %H:%M:%S")
        audit_line = (
            f"{now_str} {MYHOSTNAME} postfix/audit[1]: [MAIL_TRANSACTION] "
            f"queue_id={qid} "
            f"client_ip={client_ip} "
            f"client_name={client_name} "
            f"from=<{mail_from}> "
            f"to=<{mail_to}> "
            f"size={mail_size} "
            f"status={status} "
            f"relay={relay} "
            f'response="{response}"'
        )

        # Exibe no console
        print(f"\033[1;32m[AUDIT] {audit_line}\033[0m", flush=True)

        # Envia evento de auditoria prioritário ao SIEM (Graylog e Wazuh)
        audit_payload = f"<22>{audit_line}".encode("utf-8")
        if graylog_target:
            try:
                udp_sock.sendto(audit_payload, graylog_target)
            except Exception:
                pass
        if wazuh_target:
            try:
                udp_sock.sendto(audit_payload, wazuh_target)
            except Exception:
                pass
        return

    # 4. Limpeza da transação finalizada
    m_rem = RE_REMOVED.search(clean_line)
    if m_rem:
        qid = m_rem.group(1)
        if qid in TRANSACTIONS:
            del TRANSACTIONS[qid]
        return

def main():
    log_msg("Iniciando Log Forwarder Inteligente com Rastreabilidade Ponta a Ponta...")
    
    graylog_target = None
    if GRAYLOG_HOST:
        ip = resolve_host(GRAYLOG_HOST)
        target_ip = ip if ip else GRAYLOG_HOST
        graylog_target = (target_ip, GRAYLOG_PORT)
        log_msg(f"Graylog configurado: {GRAYLOG_HOST} ({target_ip}):{GRAYLOG_PORT} [UDP]")

    wazuh_target = None
    if WAZUH_HOST:
        ip = resolve_host(WAZUH_HOST)
        target_ip = ip if ip else WAZUH_HOST
        wazuh_target = (target_ip, WAZUH_PORT)
        log_msg(f"Wazuh configurado: {WAZUH_HOST} ({target_ip}):{WAZUH_PORT} [UDP]")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Disparo de teste de conectividade inicial para o Graylog e Wazuh
    test_payload = b"<22>mailguard postfix/forwarder[1]: MailGuard Log Forwarder iniciado com sucesso."
    if graylog_target:
        try:
            udp_sock.sendto(test_payload, graylog_target)
            log_msg(f"Ping UDP inicial enviado para Graylog {graylog_target}")
        except Exception as e:
            log_msg(f"Falha ao enviar ping inicial para Graylog: {e}")

    if wazuh_target:
        try:
            udp_sock.sendto(test_payload, wazuh_target)
            log_msg(f"Ping UDP inicial enviado para Wazuh {wazuh_target}")
        except Exception as e:
            log_msg(f"Falha ao enviar ping inicial para Wazuh: {e}")

    # Aguarda o arquivo de log existir
    while not os.path.exists(LOG_FILE):
        time.sleep(0.5)

    log_msg(f"Monitorando eventos em {LOG_FILE}...")

    current_inode = os.stat(LOG_FILE).st_ino
    file_obj = open(LOG_FILE, "r", encoding="utf-8", errors="replace")
    file_obj.seek(0, os.SEEK_END)

    while True:
        try:
            if os.path.exists(LOG_FILE):
                new_inode = os.stat(LOG_FILE).st_ino
                if new_inode != current_inode:
                    log_msg("Arquivo de log recriado. Reabrindo...")
                    file_obj.close()
                    file_obj = open(LOG_FILE, "r", encoding="utf-8", errors="replace")
                    current_inode = new_inode

            line = file_obj.readline()
            if not line:
                time.sleep(0.1)
                continue

            clean_line = line.strip()
            if not clean_line:
                continue

            # Filtra ruído de probes
            if is_noise(clean_line):
                continue

            # Exibe linha crua no console
            sys.stdout.write(line)
            sys.stdout.flush()

            # Envia linha crua para o SIEM
            syslog_payload = f"<22>{clean_line}".encode("utf-8")
            if graylog_target:
                try:
                    udp_sock.sendto(syslog_payload, graylog_target)
                except Exception:
                    pass
            if wazuh_target:
                try:
                    udp_sock.sendto(syslog_payload, wazuh_target)
                except Exception:
                    pass

            # Processa correlação para gerar a linha consolidada [MAIL_TRANSACTION]
            process_transaction_correlation(clean_line, udp_sock, graylog_target, wazuh_target)

        except Exception as e:
            log_msg(f"Erro no loop de leitura: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
