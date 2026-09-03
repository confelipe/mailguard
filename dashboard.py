#!/usr/bin/env python3
"""
MailGuard Control Center & Web Dashboard
Servidor HTTPS com TLS nativo, autenticação segura, auditoria SIEM e sincronização RBAC com K8s.
"""

import os
import sys
import ssl
import json
import socket
import hashlib
import datetime
import subprocess
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("DASHBOARD_PORT", "443"))
LOG_FILE = "/var/log/mail.log"
CIDR_FILE = "/etc/mailguard/allowed_ips.cidr"
RELAY_HOST = os.environ.get("SMTP_RELAY_HOST", "[smtp.office365.com]:25")
MYHOSTNAME = os.environ.get("MYHOSTNAME", "mailguard.local")
AUTH_USER = os.environ.get("DASHBOARD_USER", "admin").strip().lower()
AUTH_PASS = os.environ.get("DASHBOARD_PASSWORD", "Admin@2026").strip()
SSL_CERT = "/etc/ssl/mailguard/tls.crt"
SSL_KEY = "/etc/ssl/mailguard/tls.key"

SESSION_SECRET = os.environ.get("SESSION_SECRET", "mailguard-secret-key-2026")
ACTIVE_SESSIONS = set()

def generate_session_token(user):
    token = hashlib.sha256(f"{user}:{SESSION_SECRET}:{datetime.date.today()}".encode()).hexdigest()
    ACTIVE_SESSIONS.add(token)
    return token

def is_valid_session(token):
    if not token:
        return False
    expected_token = hashlib.sha256(f"{AUTH_USER}:{SESSION_SECRET}:{datetime.date.today()}".encode()).hexdigest()
    return token == expected_token or token in ACTIVE_SESSIONS

def audit_log(action_type, message, user="admin", client_ip="127.0.0.1"):
    now_str = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    log_entry = f"{now_str} {MYHOSTNAME} postfix/dashboard[1]: {action_type}: {message} [user={user}, ip={client_ip}]\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"[Dashboard Audit Error] {e}", flush=True)

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout, res.stderr
    except Exception as e:
        return 1, "", str(e)

def sync_to_k8s_configmap(cidr_content):
    """
    Sincroniza o conteúdo de allowed_ips.cidr com o ConfigMap mailguard-allowed-ips no Kubernetes via API in-cluster.
    """
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    if not os.path.exists(token_path):
        return False, "Fora do Kubernetes (token não encontrado)"

    try:
        with open(token_path, "r", encoding="utf-8") as f:
            token = f.read().strip()

        namespace = os.environ.get("NAMESPACE", "infraestrutura")
        if os.path.exists(ns_path):
            with open(ns_path, "r", encoding="utf-8") as f:
                namespace = f.read().strip()

        api_url = f"https://kubernetes.default.svc/api/v1/namespaces/{namespace}/configmaps/mailguard-allowed-ips"

        ctx = ssl.create_default_context(cafile=ca_path if os.path.exists(ca_path) else None)
        if not os.path.exists(ca_path):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        payload = json.dumps({
            "data": {
                "allowed_ips.cidr": cidr_content
            }
        }).encode("utf-8")

        req = urllib.request.Request(
            api_url,
            data=payload,
            method="PATCH",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/strategic-merge-patch+json",
                "Accept": "application/json"
            }
        )

        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            if resp.status in (200, 201):
                print(f"[Dashboard K8s Sync] ConfigMap 'mailguard-allowed-ips' atualizado com sucesso no K8s ({resp.status})", flush=True)
                return True, "ConfigMap persistido no Kubernetes"
            else:
                print(f"[Dashboard K8s Sync Warning] Retorno da API K8s: {resp.status}", flush=True)
                return False, f"HTTP {resp.status}"

    except Exception as e:
        print(f"[Dashboard K8s Sync Error] Falha ao atualizar ConfigMap no K8s: {e}", flush=True)
        return False, str(e)

def get_queue():
    code, out, _ = run_cmd("postqueue -p")
    if code != 0 or not out or "Mail queue is empty" in out:
        return []

    lines = out.strip().split("\n")
    messages = []
    current_msg = None

    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        if line_s.startswith("-Queue ID-") or line_s.startswith("-- "):
            continue

        parts = line.split()
        if len(parts) >= 6 and (len(parts[0]) >= 8 and ("*" in parts[0] or "!" in parts[0] or parts[0].isalnum())):
            if current_msg:
                messages.append(current_msg)
            
            queue_id = parts[0].replace("*", "").replace("!", "")
            size = parts[1] if len(parts) > 1 else ""
            date_str = f"{parts[2]} {parts[3]} {parts[4]}" if len(parts) > 4 else ""
            sender = parts[5] if len(parts) > 5 else ""

            current_msg = {
                "id": queue_id,
                "size": size,
                "date": date_str,
                "sender": sender,
                "recipients": [],
                "reason": ""
            }
        elif current_msg:
            if line_s.startswith("(") and line_s.endswith(")"):
                current_msg["reason"] = line_s.strip("()")
            elif "@" in line_s or len(line_s.split()) == 1:
                current_msg["recipients"].append(line_s)

    if current_msg:
        messages.append(current_msg)

    return messages

def get_allowed_ips():
    if not os.path.exists(CIDR_FILE):
        return []
    ips = []
    try:
        with open(CIDR_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if not l or l.startswith("#"):
                    continue
                parts = l.split(maxsplit=2)
                cidr = parts[0]
                action = parts[1] if len(parts) > 1 else "OK"
                desc = parts[2].lstrip("#").strip() if len(parts) > 2 else ""
                ips.append({"cidr": cidr, "action": action, "desc": desc})
    except Exception:
        pass
    return ips

def get_system_status():
    code, _, _ = run_cmd("kill -0 1")
    postfix_running = (code == 0)
    
    queue = get_queue()
    ips = get_allowed_ips()

    relay_clean = RELAY_HOST.replace("[", "").replace("]", "").strip()
    if ":" in relay_clean:
        r_host, r_port_str = relay_clean.split(":")
        r_port = int(r_port_str)
    else:
        r_host, r_port = relay_clean, 25

    relay_reachable = False
    relay_latency = 0
    try:
        t_start = datetime.datetime.now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((r_host, r_port))
        sock.close()
        t_end = datetime.datetime.now()
        relay_latency = int((t_end - t_start).total_seconds() * 1000)
        relay_reachable = True
    except Exception:
        relay_reachable = False

    return {
        "hostname": MYHOSTNAME,
        "postfix_running": postfix_running,
        "relay_host": r_host,
        "relay_port": r_port,
        "relay_reachable": relay_reachable,
        "relay_latency_ms": relay_latency,
        "queue_count": len(queue),
        "allowed_ips_count": len(ips)
    }

LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - MailGuard Control Center</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0b1329; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-card { background-color: #162038; border: 1px solid #29385c; border-radius: 16px; width: 100%; max-width: 420px; padding: 2.5rem; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
        .form-control { background-color: #070c1a; border: 1px solid #29385c; color: #fff; padding: 0.75rem 1rem; border-radius: 8px; }
        .form-control:focus { background-color: #070c1a; border-color: #38bdf8; box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.2); color: #fff; }
        .btn-login { background-color: #0284c7; border: none; padding: 0.75rem; border-radius: 8px; font-weight: 600; width: 100%; }
        .btn-login:hover { background-color: #0369a1; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="text-center mb-4">
            <div class="d-inline-flex p-3 bg-primary bg-opacity-10 rounded-4 text-primary border border-primary border-opacity-25 mb-3">
                <i class="fa-solid fa-shield-halved fa-2x"></i>
            </div>
            <h3 class="fw-bold mb-1">MailGuard</h3>
            <small class="text-secondary">Acesso Restrito • Painel Administrativo</small>
        </div>
        
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="mb-3">
                <label class="form-label small text-secondary fw-semibold">USUÁRIO</label>
                <div class="input-group">
                    <span class="input-group-text bg-dark border-secondary text-secondary"><i class="fa-solid fa-user"></i></span>
                    <input type="text" id="username" class="form-control" placeholder="admin" required autofocus>
                </div>
            </div>
            <div class="mb-4">
                <label class="form-label small text-secondary fw-semibold">SENHA</label>
                <div class="input-group">
                    <span class="input-group-text bg-dark border-secondary text-secondary"><i class="fa-solid fa-lock"></i></span>
                    <input type="password" id="password" class="form-control" placeholder="••••••••" required>
                </div>
            </div>
            <button type="submit" id="btnLogin" class="btn btn-login text-white mb-3">
                <i class="fa-solid fa-right-to-bracket me-2"></i>Entrar no Sistema
            </button>
            <div id="loginAlert" class="alert alert-danger py-2 small text-center" style="display:none;"></div>
        </form>
        <div class="text-center mt-3">
            <small class="text-muted"><i class="fa-solid fa-lock me-1 text-success"></i>Conexão Segura TLS (HTTPS)</small>
        </div>
    </div>

    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const btn = document.getElementById('btnLogin');
            const alertBox = document.getElementById('loginAlert');
            const user = document.getElementById('username').value.trim();
            const pass = document.getElementById('password').value.trim();

            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Autenticando...';
            alertBox.style.display = 'none';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: user, password: pass })
                });
                const data = await res.json();
                if (data.success) {
                    window.location.reload();
                } else {
                    alertBox.innerText = data.error || 'Credenciais inválidas.';
                    alertBox.style.display = 'block';
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-right-to-bracket me-2"></i>Entrar no Sistema';
                }
            } catch (err) {
                alertBox.innerText = 'Erro ao conectar ao servidor.';
                alertBox.style.display = 'block';
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-right-to-bracket me-2"></i>Entrar no Sistema';
            }
        }
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailGuard - Painel de Controle</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0b1329; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { background-color: #162038; border: 1px solid #29385c; border-radius: 12px; }
        .card-header { background-color: #162038; border-bottom: 1px solid #29385c; font-weight: 600; }
        .badge-status { font-size: 0.9rem; padding: 0.4rem 0.8rem; border-radius: 20px; }
        .log-terminal { background-color: #070c1a; color: #38bdf8; font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.82rem; height: 380px; overflow-y: scroll; padding: 12px; border-radius: 8px; border: 1px solid #29385c; white-space: pre-wrap; }
        .btn-action { border-radius: 8px; font-weight: 500; }
        .table { color: #cbd5e1; }
        .table-hover tbody tr:hover { background-color: #1f2d4e; }
        .nav-tabs .nav-link { color: #94a3b8; border: none; font-weight: 500; }
        .nav-tabs .nav-link.active { color: #38bdf8; background-color: transparent; border-bottom: 2px solid #38bdf8; }
        .badge-https { background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); font-size: 0.75rem; }
    </style>
</head>
<body class="p-3 p-md-4">
    <div class="container-fluid max-w-7xl">
        <!-- Header -->
        <div class="d-flex flex-wrap justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary border-opacity-25">
            <div class="d-flex align-items-center gap-3">
                <div class="p-3 bg-primary bg-opacity-10 rounded-3 text-primary border border-primary border-opacity-25 position-relative">
                    <i class="fa-solid fa-shield-halved fa-2x"></i>
                    <i class="fa-solid fa-lock position-absolute bottom-0 end-0 p-1 text-success fs-6"></i>
                </div>
                <div>
                    <h3 class="mb-0 fw-bold">MailGuard <span class="badge bg-primary fs-6 ms-2">v3.4</span> <span class="badge badge-https ms-1"><i class="fa-solid fa-lock me-1"></i>HTTPS TLS</span></h3>
                    <small class="text-secondary">SMTP Relay Corporativo Seguro • Direct Send</small>
                </div>
            </div>
            <div class="d-flex gap-2 align-items-center mt-3 mt-md-0">
                <span id="header-status-badge" class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25 badge-status">
                    <i class="fa-solid fa-circle-check me-1"></i> Postfix Ativo
                </span>
                <button onclick="refreshAll()" class="btn btn-outline-secondary btn-sm btn-action">
                    <i class="fa-solid fa-arrows-rotate me-1"></i> Atualizar
                </button>
                <button onclick="logout()" class="btn btn-outline-danger btn-sm btn-action" title="Sair da Sessão">
                    <i class="fa-solid fa-power-off me-1"></i> Sair
                </button>
            </div>
        </div>

        <!-- Metric Cards -->
        <div class="row g-3 mb-4">
            <div class="col-12 col-sm-6 col-xl-3">
                <div class="card p-3 shadow-sm">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small fw-semibold">STATUS DO RELAY</span>
                            <h4 id="metric-relay" class="mt-2 mb-0 fw-bold text-success">Verificando...</h4>
                        </div>
                        <div class="p-3 bg-success bg-opacity-10 text-success rounded-3"><i class="fa-solid fa-cloud-arrow-up fa-lg"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-sm-6 col-xl-3">
                <div class="card p-3 shadow-sm">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small fw-semibold">FILA DE E-MAILS</span>
                            <h4 id="metric-queue" class="mt-2 mb-0 fw-bold text-info">0 mensagens</h4>
                        </div>
                        <div class="p-3 bg-info bg-opacity-10 text-info rounded-3"><i class="fa-solid fa-envelope-open-text fa-lg"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-sm-6 col-xl-3">
                <div class="card p-3 shadow-sm">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small fw-semibold">IPS / REDES AUTORIZADAS</span>
                            <h4 id="metric-ips" class="mt-2 mb-0 fw-bold text-warning">0 regras</h4>
                        </div>
                        <div class="p-3 bg-warning bg-opacity-10 text-warning rounded-3"><i class="fa-solid fa-network-wired fa-lg"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-sm-6 col-xl-3">
                <div class="card p-3 shadow-sm">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="text-secondary small fw-semibold">AUDITORIA SIEM</span>
                            <h5 class="mt-2 mb-0 fw-bold text-success"><i class="fa-solid fa-satellite-dish me-1"></i> Graylog & Wazuh</h5>
                        </div>
                        <div class="p-3 bg-primary bg-opacity-10 text-primary rounded-3"><i class="fa-solid fa-fingerprint fa-lg"></i></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <ul class="nav nav-tabs mb-4" id="mainTab" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="queue-tab" data-bs-toggle="tab" data-bs-target="#queue-pane" type="button" role="tab">
                    <i class="fa-solid fa-inbox me-2"></i>Fila de Mensagens (<span id="tab-queue-count">0</span>)
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs-pane" type="button" role="tab">
                    <i class="fa-solid fa-terminal me-2"></i>Logs em Tempo Real
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ips-tab" data-bs-toggle="tab" data-bs-target="#ips-pane" type="button" role="tab">
                    <i class="fa-solid fa-shield-virus me-2"></i>IPs Permitidos
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="test-tab" data-bs-toggle="tab" data-bs-target="#test-pane" type="button" role="tab">
                    <i class="fa-solid fa-paper-plane me-2"></i>Teste de Envio
                </button>
            </li>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="mainTabContent">
            <!-- 1. QUEUE TAB -->
            <div class="tab-pane fade show active" id="queue-pane" role="tabpanel">
                <div class="card shadow-sm">
                    <div class="card-header d-flex justify-content-between align-items-center py-3">
                        <span class="fs-6"><i class="fa-solid fa-list-check me-2 text-primary"></i>Mensagens Retidas / Em Envio</span>
                        <div class="d-flex gap-2">
                            <button onclick="flushQueue()" class="btn btn-primary btn-sm btn-action">
                                <i class="fa-solid fa-bolt me-1"></i> Forçar Reenvio (Flush)
                            </button>
                            <button onclick="purgeQueue()" class="btn btn-outline-danger btn-sm btn-action">
                                <i class="fa-solid fa-trash-can me-1"></i> Zerar Toda a Fila
                            </button>
                        </div>
                    </div>
                    <div class="card-body p-0 table-responsive">
                        <table class="table table-hover align-middle mb-0">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th>
                                    <th>Data / Hora</th>
                                    <th>Tamanho</th>
                                    <th>Remetente (From)</th>
                                    <th>Destinatário (To)</th>
                                    <th>Motivo / Status</th>
                                    <th class="text-end pe-3">Ações</th>
                                </tr>
                            </thead>
                            <tbody id="queue-table-body">
                                <tr>
                                    <td colspan="7" class="text-center py-4 text-secondary">
                                        <i class="fa-solid fa-check-circle text-success fs-4 d-block mb-2"></i>
                                        A fila de e-mails está vazia. Todas as mensagens foram entregues!
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- 2. LOGS TAB -->
            <div class="tab-pane fade" id="logs-pane" role="tabpanel">
                <div class="card shadow-sm">
                    <div class="card-header d-flex justify-content-between align-items-center py-3">
                        <span class="fs-6"><i class="fa-solid fa-scroll me-2 text-primary"></i>Últimos Logs do Postfix & Auditoria (/var/log/mail.log)</span>
                        <div class="d-flex gap-2 align-items-center">
                            <input type="text" id="log-search" onkeyup="filterLogs()" placeholder="Filtrar por e-mail, AUDIT, IP, status..." class="form-control form-control-sm bg-dark text-light border-secondary" style="width: 280px;">
                            <button onclick="loadLogs()" class="btn btn-outline-secondary btn-sm"><i class="fa-solid fa-rotate"></i></button>
                        </div>
                    </div>
                    <div class="card-body p-2">
                        <div id="log-terminal" class="log-terminal">Carregando logs...</div>
                    </div>
                </div>
            </div>

            <!-- 3. IPS TAB -->
            <div class="tab-pane fade" id="ips-pane" role="tabpanel">
                <div class="row g-3">
                    <div class="col-12 col-lg-8">
                        <div class="card shadow-sm">
                            <div class="card-header py-3">
                                <span class="fs-6"><i class="fa-solid fa-table-list me-2 text-warning"></i>Lista de IPs e Sub-redes Autorizadas</span>
                            </div>
                            <div class="card-body p-0 table-responsive">
                                <table class="table table-hover align-middle mb-0">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>IP / CIDR</th>
                                            <th>Ação</th>
                                            <th>Identificação / Descrição</th>
                                            <th class="text-end pe-3">Remover</th>
                                        </tr>
                                    </thead>
                                    <tbody id="ips-table-body">
                                        <tr><td colspan="4" class="text-center py-3">Carregando regras...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-lg-4">
                        <div class="card shadow-sm">
                            <div class="card-header py-3">
                                <span class="fs-6"><i class="fa-solid fa-plus me-2 text-success"></i>Adicionar IP / Servidor</span>
                            </div>
                            <div class="card-body">
                                <form id="form-add-ip" onsubmit="addIp(event)">
                                    <div class="mb-3">
                                        <label class="form-label small text-secondary">Endereço IP ou Sub-rede (CIDR)</label>
                                        <input type="text" id="input-ip" class="form-control bg-dark text-light border-secondary" placeholder="Ex: 192.168.1.100/32" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label small text-secondary">Descrição / Nome do Sistema</label>
                                        <input type="text" id="input-desc" class="form-control bg-dark text-light border-secondary" placeholder="Ex: Servidor de Aplicacao">
                                    </div>
                                    <button type="submit" id="btn-add-ip" class="btn btn-success w-100 btn-action">
                                        <i class="fa-solid fa-check me-1"></i> Autorizar IP & Auditar
                                    </button>
                                    <div id="ip-alert" class="alert alert-danger py-2 small mt-2" style="display:none;"></div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 4. TEST TAB -->
            <div class="tab-pane fade" id="test-pane" role="tabpanel">
                <div class="card shadow-sm max-w-2xl">
                    <div class="card-header py-3">
                        <span class="fs-6"><i class="fa-solid fa-envelope-circle-check me-2 text-primary"></i>Disparo de Teste de E-mail via Relay</span>
                    </div>
                    <div class="card-body">
                        <form id="form-send-test" onsubmit="sendTestMail(event)">
                            <div class="row g-3">
                                <div class="col-12 col-md-6">
                                    <label class="form-label small text-secondary">Destinatário</label>
                                    <input type="email" id="test-recipient" class="form-control bg-dark text-light border-secondary" placeholder="admin@example.com" required>
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label small text-secondary">Remetente (From)</label>
                                    <input type="email" id="test-sender" class="form-control bg-dark text-light border-secondary" value="notificacoes@example.com">
                                </div>
                                <div class="col-12">
                                    <label class="form-label small text-secondary">Assunto</label>
                                    <input type="text" id="test-subject" class="form-control bg-dark text-light border-secondary" value="Teste de Envio - MailGuard Web Dashboard">
                                </div>
                                <div class="col-12">
                                    <label class="form-label small text-secondary">Corpo da Mensagem</label>
                                    <textarea id="test-body" rows="3" class="form-control bg-dark text-light border-secondary">Olá! Este é um teste disparado diretamente do Dashboard Web do MailGuard (HTTPS) para validar a entrega.</textarea>
                                </div>
                                <div class="col-12">
                                    <button type="submit" id="btn-submit-test" class="btn btn-primary btn-action">
                                        <i class="fa-solid fa-paper-plane me-1"></i> Disparar E-mail de Teste
                                    </button>
                                </div>
                            </div>
                        </form>
                        <div id="test-result" class="mt-4" style="display:none;"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let rawLogs = "";

        async function fetchAPI(url, options = {}) {
            try {
                const res = await fetch(url, options);
                if (res.status === 401) {
                    window.location.reload();
                    return { error: "Não autorizado" };
                }
                return await res.json();
            } catch(e) {
                console.error(e);
                return { error: e.toString() };
            }
        }

        async function loadStatus() {
            const data = await fetchAPI('/api/status');
            if (data.postfix_running) {
                document.getElementById('header-status-badge').className = "badge bg-success bg-opacity-25 text-success border border-success border-opacity-25 badge-status";
                document.getElementById('header-status-badge').innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> Postfix Ativo';
            } else {
                document.getElementById('header-status-badge').className = "badge bg-danger bg-opacity-25 text-danger border border-danger border-opacity-25 badge-status";
                document.getElementById('header-status-badge').innerHTML = '<i class="fa-solid fa-triangle-exclamation me-1"></i> Postfix Parado';
            }

            if (data.relay_reachable) {
                document.getElementById('metric-relay').innerText = `Conectado (${data.relay_latency_ms}ms)`;
                document.getElementById('metric-relay').className = "mt-2 mb-0 fw-bold text-success";
            } else {
                document.getElementById('metric-relay').innerText = "Inalcançável";
                document.getElementById('metric-relay').className = "mt-2 mb-0 fw-bold text-danger";
            }

            document.getElementById('metric-queue').innerText = data.queue_count + " mensagens";
            document.getElementById('metric-ips').innerText = data.allowed_ips_count + " regras";
            document.getElementById('tab-queue-count').innerText = data.queue_count;
        }

        async function loadQueue() {
            const list = await fetchAPI('/api/queue');
            const tbody = document.getElementById('queue-table-body');
            if (!Array.isArray(list) || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-secondary"><i class="fa-solid fa-check-circle text-success fs-4 d-block mb-2"></i>A fila de e-mails está vazia. Todas as mensagens foram entregues!</td></tr>`;
                return;
            }
            tbody.innerHTML = list.map(m => `
                <tr>
                    <td class="fw-bold text-primary">${m.id}</td>
                    <td><small class="text-secondary">${m.date}</small></td>
                    <td><small>${m.size}B</small></td>
                    <td><span class="badge bg-secondary bg-opacity-50 text-light">${m.sender}</span></td>
                    <td><span class="badge bg-dark border border-secondary text-info">${m.recipients.join(', ')}</span></td>
                    <td><small class="text-warning">${m.reason || 'Em processamento'}</small></td>
                    <td class="text-end pe-3">
                        <button onclick="deleteMsg('${m.id}')" class="btn btn-outline-danger btn-sm" title="Excluir"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        }

        async function loadLogs() {
            const data = await fetchAPI('/api/logs');
            rawLogs = data.logs || "";
            filterLogs();
        }

        function filterLogs() {
            const search = document.getElementById('log-search').value.toLowerCase();
            const term = document.getElementById('log-terminal');
            if (!search) {
                term.innerText = rawLogs;
            } else {
                const filtered = rawLogs.split('\\n').filter(l => l.toLowerCase().includes(search)).join('\\n');
                term.innerText = filtered || "Nenhum log encontrado para o filtro.";
            }
            term.scrollTop = term.scrollHeight;
        }

        async function loadIps() {
            const list = await fetchAPI('/api/ips');
            const tbody = document.getElementById('ips-table-body');
            if (!Array.isArray(list) || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center py-3 text-secondary">Nenhuma regra cadastrada.</td></tr>`;
                return;
            }
            tbody.innerHTML = list.map(i => `
                <tr>
                    <td class="fw-bold text-light">${i.cidr}</td>
                    <td><span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25">${i.action}</span></td>
                    <td><span class="text-secondary">${i.desc || '-'}</span></td>
                    <td class="text-end pe-3">
                        <button onclick="deleteIp('${i.cidr}')" class="btn btn-outline-danger btn-sm"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        }

        async function flushQueue() {
            await fetchAPI('/api/queue/flush', { method: 'POST' });
            alert("Solicitação de reenvio da fila disparada com sucesso!");
            refreshAll();
        }

        async function purgeQueue() {
            if (confirm("Tem certeza que deseja zerar TODA a fila de e-mails?")) {
                await fetchAPI('/api/queue/delete', { method: 'POST', body: JSON.stringify({ id: 'ALL' }) });
                refreshAll();
            }
        }

        async function deleteMsg(id) {
            await fetchAPI('/api/queue/delete', { method: 'POST', body: JSON.stringify({ id }) });
            refreshAll();
        }

        async function addIp(e) {
            e.preventDefault();
            const alertBox = document.getElementById('ip-alert');
            const ip = document.getElementById('input-ip').value.trim();
            const desc = document.getElementById('input-desc').value.trim();
            alertBox.style.display = 'none';

            const res = await fetchAPI('/api/ips/add', { method: 'POST', body: JSON.stringify({ ip, desc }) });
            if (res.success) {
                document.getElementById('input-ip').value = '';
                document.getElementById('input-desc').value = '';
                loadIps();
                loadStatus();
            } else {
                alertBox.innerText = res.error || 'Erro ao adicionar IP.';
                alertBox.style.display = 'block';
            }
        }

        async function deleteIp(ip) {
            if (confirm(`Remover permissão para ${ip}?`)) {
                const res = await fetchAPI('/api/ips/delete', { method: 'POST', body: JSON.stringify({ ip }) });
                if (!res.success) {
                    alert(res.error || 'Erro ao remover IP');
                }
                loadIps();
                loadStatus();
            }
        }

        async function sendTestMail(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-submit-test');
            const resDiv = document.getElementById('test-result');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Enviando...';

            const payload = {
                recipient: document.getElementById('test-recipient').value,
                sender: document.getElementById('test-sender').value,
                subject: document.getElementById('test-subject').value,
                body: document.getElementById('test-body').value
            };

            const data = await fetchAPI('/api/send_test', { method: 'POST', body: JSON.stringify(payload) });
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-paper-plane me-1"></i> Disparar E-mail de Teste';
            resDiv.style.display = 'block';

            if (data.success) {
                resDiv.innerHTML = `<div class="alert alert-success border border-success"><i class="fa-solid fa-circle-check me-2"></i>E-mail entregue com sucesso no Postfix!<br><small class="text-secondary">${data.message}</small></div>`;
            } else {
                resDiv.innerHTML = `<div class="alert alert-danger border border-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i>Falha no envio:<br><small>${data.error || data.message}</small></div>`;
            }
            refreshAll();
        }

        async function logout() {
            await fetchAPI('/api/logout', { method: 'POST' });
            window.location.reload();
        }

        function refreshAll() {
            loadStatus();
            loadQueue();
            loadLogs();
            loadIps();
        }

        setInterval(refreshAll, 5000);
        window.onload = refreshAll;
    </script>
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    def get_cookie(self, name):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookies = cookie_header.split(";")
        for c in cookies:
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    def is_authenticated(self):
        token = self.get_cookie("mailguard_session")
        return is_valid_session(token)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        
        if url.path == "/":
            if not self.is_authenticated():
                body = LOGIN_TEMPLATE.encode("utf-8")
            else:
                body = DASHBOARD_TEMPLATE.encode("utf-8")
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not self.is_authenticated():
            self.send_json({"error": "Não autorizado"}, 401)
            return

        if url.path == "/api/status":
            self.send_json(get_system_status())
        elif url.path == "/api/queue":
            self.send_json(get_queue())
        elif url.path == "/api/ips":
            self.send_json(get_allowed_ips())
        elif url.path == "/api/logs":
            logs = ""
            if os.path.exists(LOG_FILE):
                try:
                    _, out, _ = run_cmd(f"tail -n 150 {LOG_FILE}")
                    logs = out
                except Exception:
                    pass
            self.send_json({"logs": logs})
        else:
            self.send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        client_ip = self.client_address[0]
        url = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        data = {}
        if post_data:
            try:
                data = json.loads(post_data.decode("utf-8"))
            except Exception:
                pass

        if url.path == "/api/login":
            user = data.get("username", "").strip().lower()
            password = data.get("password", "").strip()

            if user == AUTH_USER and password == AUTH_PASS:
                token = generate_session_token(user)
                audit_log("AUDIT", f"Login realizado com sucesso pelo usuário '{user}'", user=user, client_ip=client_ip)
                
                body = json.dumps({"success": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"mailguard_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                audit_log("SECURITY", f"Tentativa de login FALHA para o usuário '{user}'", user="anonymous", client_ip=client_ip)
                self.send_json({"error": "Usuário ou senha inválidos."}, 401)
            return

        if url.path == "/api/logout":
            token = self.get_cookie("mailguard_session")
            if token in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS.remove(token)
            audit_log("AUDIT", f"Logout realizado pelo usuário '{AUTH_USER}'", user=AUTH_USER, client_ip=client_ip)
            
            body = json.dumps({"success": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", "mailguard_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if not self.is_authenticated():
            self.send_json({"error": "Não autorizado"}, 401)
            return

        user = AUTH_USER

        if url.path == "/api/queue/flush":
            run_cmd("postqueue -f")
            audit_log("AUDIT", "Forçado reenvio de todas as mensagens retidas na fila (Flush)", user=user, client_ip=client_ip)
            self.send_json({"success": True, "message": "Flush acionado"})
        elif url.path == "/api/queue/delete":
            msg_id = data.get("id", "")
            if msg_id:
                if msg_id == "ALL":
                    run_cmd("postsuper -d ALL")
                    audit_log("AUDIT", "Fila de e-mails ZERADA completamente (ALL)", user=user, client_ip=client_ip)
                else:
                    run_cmd(f"postsuper -d {msg_id}")
                    audit_log("AUDIT", f"Mensagem ID {msg_id} removida da fila", user=user, client_ip=client_ip)
            self.send_json({"success": True})
        elif url.path == "/api/ips/add":
            ip = data.get("ip", "").strip()
            desc = data.get("desc", "").strip()
            if ip:
                if "/" not in ip:
                    ip = f"{ip}/32"
                entry = f"{ip}    OK"
                if desc:
                    entry += f" # {desc}"
                try:
                    os.makedirs(os.path.dirname(CIDR_FILE), exist_ok=True)
                    with open(CIDR_FILE, "a", encoding="utf-8") as f:
                        f.write(f"\n{entry}\n")
                    run_cmd("postfix reload")
                    audit_log("AUDIT", f"IP {ip} adicionado à lista de permissões (Desc: {desc})", user=user, client_ip=client_ip)
                    
                    # Sincroniza com o ConfigMap do Kubernetes
                    with open(CIDR_FILE, "r", encoding="utf-8") as f:
                        full_content = f.read()
                    sync_to_k8s_configmap(full_content)
                    
                    self.send_json({"success": True})
                except Exception as e:
                    self.send_json({"error": f"Erro de gravação: {str(e)}"}, 500)
            else:
                self.send_json({"error": "IP obrigatório"}, 400)
        elif url.path == "/api/ips/delete":
            ip = data.get("ip", "").strip()
            if ip and os.path.exists(CIDR_FILE):
                try:
                    with open(CIDR_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    new_lines = [l for l in lines if not l.strip().startswith(ip)]
                    full_content = "".join(new_lines)
                    with open(CIDR_FILE, "w", encoding="utf-8") as f:
                        f.write(full_content)
                    run_cmd("postfix reload")
                    audit_log("AUDIT", f"IP {ip} removido da lista de permissões", user=user, client_ip=client_ip)
                    
                    # Sincroniza com o ConfigMap do Kubernetes
                    sync_to_k8s_configmap(full_content)
                    
                    self.send_json({"success": True})
                except Exception as e:
                    self.send_json({"error": f"Erro ao remover IP: {str(e)}"}, 500)
            else:
                self.send_json({"error": "IP não encontrado"}, 400)
        elif url.path == "/api/send_test":
            to = data.get("recipient", "")
            sender = data.get("sender", "notificacoes@example.com")
            subject = data.get("subject", "Teste de Envio")
            body_txt = data.get("body", "Mensagem de teste")
            if not to:
                self.send_json({"error": "Destinatário obrigatório"}, 400)
                return

            cmd = f'printf "Subject: {subject}\\nFrom: {sender}\\nTo: {to}\\n\\n{body_txt}\\n" | sendmail -f "{sender}" "{to}"'
            code, out, err = run_cmd(cmd)
            if code == 0:
                audit_log("AUDIT", f"E-mail de teste disparado para {to} (From: {sender})", user=user, client_ip=client_ip)
                self.send_json({"success": True, "message": "Mensagem enfileirada no Postfix para entrega"})
            else:
                audit_log("AUDIT", f"Falha no disparo de teste para {to}: {err or out}", user=user, client_ip=client_ip)
                self.send_json({"error": err or out}, 500)
        else:
            self.send_json({"error": "Not Found"}, 404)

def run_server():
    server = HTTPServer(("0.0.0.0", PORT), RequestHandler)
    
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            print(f"[Dashboard] Servidor HTTPS iniciado na porta {PORT} com TLS ativo!", flush=True)
        except Exception as e:
            print(f"[Dashboard TLS Warning] Falha ao carregar TLS: {e}. Iniciando HTTP padrão...", flush=True)
    else:
        print(f"[Dashboard] Certificados não encontrados em {SSL_CERT}. Iniciando HTTP na porta {PORT}...", flush=True)

    server.serve_forever()

if __name__ == "__main__":
    run_server()
