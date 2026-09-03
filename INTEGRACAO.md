# Guia Rápido de Integração: MailGuard SMTP Relay

Este manual orienta desenvolvedores, equipes de DevOps e administradores de sistemas a configurarem suas aplicações e servidores (**GLPI, Zabbix, Grafana, WordPress, scripts, microserviços**) para envio de e-mails corporativos através do **MailGuard Relay**.

---

## ⚡ 1. Parâmetros Essenciais de Conexão SMTP

| Parâmetro | Valor a Configurar | Observações |
|---|---|---|
| **Servidor SMTP (Host)** | `mailguard.local` *(ou IP do LoadBalancer)* | Hostname/DNS interno do MailGuard |
| **Porta Padrão** | `25` (ou `587`) | `25` (Plain / STARTTLS) ou `587` (Submission STARTTLS) |
| **Autenticação (SMTP Auth)** | **NÃO / DESABILITADA** | Não utilize usuário e senha |
| **Criptografia / Segurança** | `STARTTLS` *(Opcional / Recomendado)* | Aceita também conexões Plain na rede interna |
| **Remetente (`From`)** | Qualquer e-mail válido do domínio | Ex: `notificacoes@seu-dominio.com`, `glpi@seu-dominio.com` |

> [!IMPORTANT]
> **Requisito Obrigatório (Whitelist de IP):**  
> O MailGuard utiliza segurança baseada em rede. Antes de realizar o primeiro envio, **o IP ou range CIDR da sua máquina/servidor deve ser cadastrado na Whitelist de IPs permitidos** (via Painel Web ou comando `./manage_ips.sh add <IP>`).

---

## 🛠️ 2. Exemplos Prontos de Configuração por Sistema

### 🏢 A. GLPI
No menu **Configurar > Notificações > Configuração dos Acompanhamentos por E-mail**:
- **Modo de envio:** `SMTP`
- **Host SMTP:** `mailguard.local` (ou IP do LoadBalancer)
- **Porta:** `25`
- **Usuário SMTP:** *(deixe em branco)*
- **Senha SMTP:** *(deixe em branco)*
- **Autenticação SMTP Requerida:** `Não`
- **Segurança SMTP:** `Nenhum` ou `STARTTLS`

---

### 📊 B. Zabbix (Media Types)
No menu **Administration > Media Types > E-mail**:
- **SMTP server:** `mailguard.local`
- **SMTP server port:** `25`
- **SMTP helo:** `zabbix.local`
- **SMTP email:** `zabbix-alertas@seu-dominio.com`
- **Connection security:** `None` ou `STARTTLS`
- **Authentication:** `None`

---

### 📈 C. Grafana (`grafana.ini`)
No arquivo de configuração do Grafana ou ConfigMap:
```ini
[smtp]
enabled = true
host = mailguard.local:25
user =
password =
skip_verify = true
from_address = grafana@seu-dominio.com
from_name = Grafana Alertas
```

---

### 🌐 D. WordPress (`wp-config.php` ou Plugin SMTP)
- **Mailer:** `Other SMTP`
- **SMTP Host:** `mailguard.local`
- **Encryption:** `None` ou `TLS`
- **SMTP Port:** `25` (ou `587`)
- **Authentication:** `No / Off`

---

## 💻 3. Exemplos em Linguagens de Programação & Scripts

### 🐍 Python (`smtplib`)
```python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Corpo do e-mail de alerta corporativo.")
msg['Subject'] = "Alerta do Sistema"
msg['From'] = "sistema@seu-dominio.com"
msg['To'] = "destinatario@seu-dominio.com"

# Envio direto sem credenciais
with smtplib.SMTP("mailguard.local", 25) as server:
    server.send_message(msg)
    print("E-mail enviado com sucesso!")
```

---

### 🐘 PHP (`mail()` ou `PHPMailer`)
```php
<?php
use PHPMailer\PHPMailer\PHPMailer;

$mail = new PHPMailer(true);
$mail->isSMTP();
$mail->Host       = 'mailguard.local';
$mail->SMTPAuth   = false;
$mail->Port       = 25;

$mail->setFrom('sistema@seu-dominio.com', 'Sistema Automático');
$mail->addAddress('destinatario@seu-dominio.com');
$mail->Subject = 'Notificação de Processamento';
$mail->Body    = 'Processo concluído com êxito.';

$mail->send();
?>
```

---

### ☕ Java / Spring Boot (`application.yml`)
```yaml
spring:
  mail:
    host: mailguard.local
    port: 25
    properties:
      mail:
        smtp:
          auth: false
          starttls:
            enable: true
```

---

### 🐧 Linux Shell Script (`nc` / `netcat` ou `mailx`)
```bash
# Teste via Netcat direto
nc mailguard.local 25 <<EOF
EHLO meu-servidor.local
MAIL FROM:<sistema@seu-dominio.com>
RCPT TO:<destinatario@seu-dominio.com>
DATA
Subject: Teste via Terminal
From: <sistema@seu-dominio.com>
To: <destinatario@seu-dominio.com>

Mensagem de teste de envio.
.
QUIT
EOF
```

---

## 🔍 4. Como Acompanhar a Entrega do seu E-mail

1. **Dashboard Web:** Acesse `https://mailguard.local` e consulte a aba **Logs em Tempo Real** ou **Fila de Mensagens**.
2. **Evento de Auditoria:** O MailGuard gera automaticamente uma linha de auditoria com status final:
   ```log
   [MAIL_TRANSACTION] queue_id=4Z8N1x client_ip=192.168.1.50 from=<sistema@seu-dominio.com> to=<destinatario@seu-dominio.com> status=sent
   ```
