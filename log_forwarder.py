#!/usr/bin/env python3
import os
import sys
import time
import socket

LOG_FILE = "/var/log/mail.log"
GRAYLOG_HOST = os.environ.get("GRAYLOG_HOST", "graylog.local")
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_PORT", "514"))
WAZUH_HOST = os.environ.get("WAZUH_HOST", "wazuh.local")
WAZUH_PORT = int(os.environ.get("WAZUH_PORT", "1514"))

NOISE_PATTERNS = [
    "commands=0/0",
    "lost connection after CONNECT",
    "the Postfix mail system is running",
    "improper command pipelining after CONNECT",
    "connect from 10-",
    "connect from 172-",
    "connect from 192-",
]

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

def main():
    log_msg("Iniciando Log Forwarder Inteligente...")
    
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

    # Aguarda o arquivo existir
    while not os.path.exists(LOG_FILE):
        time.sleep(0.5)

    log_msg(f"Monitorando eventos em {LOG_FILE}...")

    current_inode = os.stat(LOG_FILE).st_ino
    file_obj = open(LOG_FILE, "r", encoding="utf-8", errors="replace")
    file_obj.seek(0, os.SEEK_END)

    while True:
        try:
            # Verifica se o arquivo foi recriado (troca de inode)
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

            # Filtra ruído de probes / health checks
            if is_noise(clean_line):
                continue

            # Exibe transações reais no stdout do container
            sys.stdout.write(line)
            sys.stdout.flush()

            # Formata Syslog RFC 3164 (Facility mail=2, Severity info=6 => Priority 22)
            syslog_payload = f"<22>{clean_line}".encode("utf-8")

            # Envia para Graylog
            if graylog_target:
                try:
                    udp_sock.sendto(syslog_payload, graylog_target)
                except Exception as e:
                    log_msg(f"Erro ao enviar para Graylog: {e}")

            # Envia para Wazuh
            if wazuh_target:
                try:
                    udp_sock.sendto(syslog_payload, wazuh_target)
                except Exception as e:
                    log_msg(f"Erro ao enviar para Wazuh: {e}")

        except Exception as e:
            log_msg(f"Erro no loop de leitura: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
