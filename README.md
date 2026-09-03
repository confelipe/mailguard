# MailGuard - Servidor SMTP Relay Corporativo & Painel de Controle (Kubernetes)

> **Projeto:** MailGuard MTA  
> **Status:** Ativo / Produção  
> **Versão:** `3.4`  
> **Namespace Kubernetes:** `infraestrutura`  
> **Hostname Padrão:** `mailguard.local`  
> **Painel HTTPS Seguro:** `https://mailguard.local` (Porta `443` com Certificado TLS)  
> **Exposição de Rede:** `type: LoadBalancer` com IP Dedicado  
> **Guia para Desenvolvedores / Sistemas:** 📘 [INTEGRACAO.md](INTEGRACAO.md)  

---

## 📖 1. Visão Geral da Arquitetura

O **MailGuard** é um servidor MTA (*Mail Transfer Agent*) baseado em Postfix 3.8, conteinerizado em Alpine Linux e operado sobre cluster Kubernetes.

Atua como o **ponto centralizado de saída de e-mails** para:
1. **Aplicações e CronJobs no Cluster K8s**: GLPI, Zabbix, Grafana, PHPIPAM, Notificações de CI/CD.
2. **Servidores e VMs fora do Cluster**: Servidores físicos e virtuais nas sub-redes corporativas (`10.x.x.x`, `172.x.x.x`, `192.168.x.x`).
3. **Entrega Segura no Provedor SMTP / Office 365**:
   - Entrega via conector inbound `[smtp.office365.com]:25` (ou endpoint customizado).
   - Criptografia obrigatória com `STARTTLS` (TLSv1.2 e TLSv1.3 com validação de CA).
   - Preservação dos cabeçalhos originais de remetente sem necessidade de credenciais estáticas de usuário.

```mermaid
flowchart TD
    subgraph Internos ["Clientes e Sistemas Internos"]
        k8s_apps["Pods Kubernetes (GLPI, Zabbix, Grafana)"]
        ext_servers["Servidores Físicos / VMs Corporativas"]
        admin_user["SysAdmin / Navegador"]
    end

    subgraph MetalLB ["LoadBalancer (IP Dedicado)"]
        lb_smtp["Porta 25 (SMTP Plain)"]
        lb_sub["Porta 587 (Submission TLS)"]
        lb_https["Porta 443 (HTTPS Dashboard)"]
    end

    subgraph MailGuardPod ["Pod: MailGuard (Namespace infraestrutura)"]
        direction TB
        subgraph Engine ["MTA Postfix 3.8"]
            postfix["Postfix Engine (Hardening + Anvil)"]
            cidr["Tabela CIDR (/etc/mailguard/rules/allowed_ips.cidr)"]
            watchdog["Watchdog de ConfigMap (Reload Zero-Downtime)"]
        end

        subgraph Forwarder ["Python Log Forwarder"]
            logtail["Leitor em Tempo Real (/var/log/mail.log)"]
            tracker["Correlacionador de Transações por Queue ID"]
            filter["Filtro Anti-Ruído (Probes & Health Checks)"]
            udp_sender["Transmissor UDP Syslog (RFC 3164)"]
        end

        subgraph WebCenter ["MailGuard Web Dashboard (HTTPS)"]
            dashboard["Web App Python (Sessão Cookie & TLS)"]
            actions["Gestão de Fila (Flush/Purge), IPs e Live Logs"]
            audit["Gerador de Trilha AUDIT / SECURITY"]
        end
    end

    subgraph Destinos ["Destinos Externos & SIEM"]
        relay["Provedor SMTP / Office 365\n(STARTTLS Criptografado)"]
        graylog["Graylog\n(Syslog UDP :514)"]
        wazuh["Wazuh SIEM\n(Syslog UDP :1514)"]
    end

    k8s_apps -->|SMTP| lb_smtp
    ext_servers -->|SMTP / Submission| lb_sub
    admin_user -->|HTTPS :443| lb_https

    lb_smtp --> postfix
    lb_sub --> postfix
    lb_https --> dashboard

    postfix -->|STARTTLS :25| relay
    postfix -->|Logs de Envio| logtail
    dashboard -->|Auditoria Administrativa| logtail

    logtail --> tracker --> filter --> udp_sender
    udp_sender -->|Syslog :514| graylog
    udp_sender -->|Syslog :1514| wazuh
```

---

## 🌟 2. Recursos e Funcionalidades

### 🖥️ A. MailGuard Web Dashboard (HTTPS :443)
- **Acesso Seguro Oficial**: `https://mailguard.local` protegido com certificado TLS.
- **Autenticação Segura por Cookie (`HttpOnly`)**:
  - Sessão segura de 24 horas e botão integrado de **Logout (Sair)**.
- **Gestão Completa de Filas**:
  - Visualização de mensagens retidas com ID, data, remetente, destinatário e status de retenção.
  - **Botão "Flush Queue"**: Dispara o reprocessamento imediato da fila (`postqueue -f`).
  - **Botão "Excluir Mensagem"**: Remove mensagens retidas (`postsuper -d <ID>`).
  - **Botão "Zerar Toda a Fila"**: Limpeza de emergência em loops (`postsuper -d ALL`).
- **Live Logs com Filtro Instantâneo**:
  - Visualizador em tempo real dos logs com filtro por e-mail, IP ou status de entrega.
- **Gestão Gráfica de IPs**:
  - Cadastro e exclusão de IPs/redes autorizadas com 1 clique.
- **Disparador de Testes de Envio**:
  - Formulário para testar o envio de e-mails para qualquer endereço diretamente pela web.

---

### 🛡️ B. Rastreabilidade Ponta a Ponta & Auditoria SIEM
- **Linha de Auditoria Consolidada (`[MAIL_TRANSACTION]`)**:
  - O Log Forwarder correlaciona em tempo real os eventos do Postfix pelo `Queue ID` e transmite ao Graylog e Wazuh uma linha única contendo:
  ```log
  [MAIL_TRANSACTION] queue_id=4Z8N1x client_ip=192.168.1.50 client_name=glpi.local from=<glpi@dominio.com> to=<suporte@dominio.com> size=1542 status=sent relay=outlook.com:25 response="250 2.6.0 Queued mail for delivery"
  ```
- **Hardening Avançado de Postfix**:
  - Banner limpo (`smtpd_banner = $myhostname ESMTP MailGuard`) ocultando SO e versão.
  - Bloqueio de enumeração de caixas postais (`disable_vrfy_command = yes`).
  - HELO/EHLO mandatório.
  - Rate-Limiting com Anvil (máximo de 50 conexões simultâneas e 300 mensagens/minuto por cliente).
  - Limite de 35MB por mensagem.
- **Trilha Completa de Auditoria no Graylog & Wazuh**:
  - Qualquer alteração de IP, flush/purge de fila, login ou logout é enviada via Syslog como evento estruturado `AUDIT` / `SECURITY`.
- **Stream de Logs Limpo (Filtro Anti-Ruído)**:
  - Probes nativos silenciosos (`kill -0 1`).
  - Descarte automático de conexões de health checks vazias (`commands=0/0`, `lost connection after CONNECT`).

---

### 🌐 C. Gerenciamento Dinâmico de IPs (Zero-Downtime)
- Controlado pelo ConfigMap `mailguard-allowed-ips` montado em `/etc/mailguard/rules/allowed_ips.cidr`.
- O container monitora alterações através de um watchdog em background e recarrega o Postfix (`postfix reload`) instantaneamente sem derrubar conexões ativas.

---

## 📁 3. Estrutura de Arquivos do Projeto

```
.
├── Dockerfile                  # Imagem Alpine 3.19 (Postfix, Python3, Certs, Mailx)
├── entrypoint.sh               # Script de boot, hardening, watchdog e inicialização
├── log_forwarder.py            # Log Forwarder UDP Syslog com rastreabilidade [MAIL_TRANSACTION]
├── dashboard.py                # Servidor Web HTTPS (:443), Auth por Cookie e API REST
├── mailguard.yaml              # Manifestos K8s (Certificate, ConfigMaps, Deployment, Service)
├── deploy.sh                   # Script de build, push e deploy com variáveis do .env
├── manage_ips.sh               # CLI interativa para gestão de IPs autorizados
├── test_mail.sh                # Script utilitário para disparo de e-mails de teste
├── INTEGRACAO.md               # Manual prático de integração para sistemas externos
├── .env.example                # Template público de variáveis de ambiente
└── README.md                   # Documentação mestre padronizada
```

---

## 🛠️ 4. Guia de Operação & Comandos Úteis

### 4.1. Como Integrar Sistemas Externos (GLPI, Zabbix, Grafana, etc.)
Consulte o guia completo com exemplos em: 📘 **[INTEGRACAO.md](INTEGRACAO.md)**.

---

### 4.2. Como Gerenciar IPs Autorizados via CLI
Execute no terminal:

```bash
# 1. Listar regras ativas
./manage_ips.sh list

# 2. Adicionar uma nova VM / Servidor
./manage_ips.sh add 192.168.1.50/32 "Servidor Grafana"

# 3. Adicionar uma sub-rede corporativa
./manage_ips.sh add 192.168.50.0/24 "Rede Servidores"

# 4. Remover uma regra existente
./manage_ips.sh remove 192.168.1.50/32
```

---

### 4.3. Como Fazer o Deploy Automatizado via `.env`

```bash
# 1. Configurar variáveis de ambiente caso ainda não existam
cp .env.example .env
# (Edite o .env com seus dados locais)

# 2. Executar deploy completo com 1 comando
./deploy.sh
```

---

## 📊 5. Parâmetros de Configuração (`.env`)

| Parâmetro | Valor Padrão | Descrição |
|---|---|---|
| `TZ` | `America/Sao_Paulo` | Fuso horário operacional do Postfix e logs. |
| `MYHOSTNAME` | `mailguard.local` | Nome FQDN de identificação do MTA no HELO/EHLO. |
| `SMTP_RELAY_HOST` | `[smtp.office365.com]:25` | Endpoint do conector Inbound do provedor SMTP. |
| `GRAYLOG_HOST` | `graylog.local` | Host do Graylog para exportação de logs via Syslog UDP. |
| `GRAYLOG_PORT` | `514` | Porta Syslog UDP do Graylog. |
| `WAZUH_HOST` | `wazuh.local` | Host do Wazuh para eventos de segurança e auditoria. |
| `WAZUH_PORT` | `1514` | Porta Syslog UDP do Wazuh. |
| `DASHBOARD_PORT` | `443` | Porta HTTPS do painel de controle. |
| `DASHBOARD_USER` | `admin` | Usuário do painel de controle. |
| `DASHBOARD_PASSWORD`| `Admin@2026` | Senha de acesso ao painel. |
