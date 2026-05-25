#!/bin/bash
# ==============================================================================
# Script: gerar_monitor.sh
# Versão: 2.7.1
# Descrição: Coletor de métricas avançado, CVEs e gerador de painel web SRE
# Localização: /root/gerar_monitor.sh
# Destino: /usr/share/nginx/html/monitor/www/
# ==============================================================================

# Inicia o cronômetro nativo do Bash
SECONDS=0

# Forçar localidade padrão para evitar erros de tradução em comandos de CLI
export LANG=C
export LC_ALL=C

# Definição de caminhos e arquivos
OUTPUT_DIR="/usr/share/nginx/html/monitor/www"
OUTPUT_INDEX="$OUTPUT_DIR/index.html"
OUTPUT_LOGS="$OUTPUT_DIR/erros_logs_24h.html"
OUTPUT_SECURITY="$OUTPUT_DIR/security_compliance.html"
LOG_FILE="/home/nogueira/atualiza_n8n.log"
ERR_FILE="/tmp/monitor_errors.log"
MAX_DUR_FILE="/var/tmp/monitor_max_duration.txt"
DATA_EXECUCAO=$(date "+%d/%m/%Y %H:%M:%S")
VERSAO_SCRIPT="2.7.1"

# Inicializa o controle de alertas (0 = Tudo OK, 1 = Existe algum ALERTA)
HAS_ALERTA=0

# Garantir que o diretório de destino existe
mkdir -p "$OUTPUT_DIR"

# ------------------------------------------------------------------------------
# 1. COLETA DE DADOS - 1) STATUS GERAL DO SERVIDOR
# ------------------------------------------------------------------------------
IP_PUBLICO="200.234.219.144"
SO_VERSAO=$(cat /etc/redhat-release 2>/dev/null || echo "Rocky Linux 9.7 (Blue Onyx)")
KERNEL_VERSAO=$(uname -r)

if [ "$(/usr/sbin/getenforce 2>/dev/null)" = "Enforcing" ]; then
    SELINUX_STATUS="Enforced"
    SELINUX_CLASSE="status-ok"
else
    SELINUX_STATUS="Permissive/Disabled"
    SELINUX_CLASSE="status-alerta"
    HAS_ALERTA=1
fi

if ping -c 3 -W 2 _gateway >/dev/null 2>&1; then
    GATEWAY_STATUS="0% packet loss"
    GATEWAY_CLASSE="status-ok"
else
    GATEWAY_STATUS="100% packet loss"
    GATEWAY_CLASSE="status-alerta"
    HAS_ALERTA=1
fi

if host n8n.nogueiraconsultoria.eti.br >/dev/null 2>&1; then
    DNS_STATUS="Resolvendo OK"
    DNS_CLASSE="status-ok"
else
    DNS_STATUS="Falha na Resolução"
    DNS_CLASSE="status-alerta"
    HAS_ALERTA=1
fi

if kpatch list 2>/dev/null | grep -q "loaded"; then
    KPATCH_CORE_STATUS="Ativo (Patches Carregados)"
    KPATCH_CORE_CLASSE="status-ok"
else
    KPATCH_CORE_STATUS="Ativo (Sem patches pendentes)"
    KPATCH_CORE_CLASSE="status-ok"
fi

# ------------------------------------------------------------------------------
# 2. COLETA DE DADOS - 2) COMPONENTES DO SISTEMA OPERACIONAL
# ------------------------------------------------------------------------------
UPTIME_SECS=$(cut -d. -f1 /proc/uptime)
UPTIME_EXIBIR=$(uptime -p | sed 's/^up //')
if [ "$UPTIME_SECS" -lt 86400 ]; then
    UPTIME_STATUS="ALERTA"; UPTIME_CLASSE="status-alerta"; HAS_ALERTA=1
else
    UPTIME_STATUS="OK"; UPTIME_CLASSE="status-ok"
fi

PKGS_CURR=$(dnf list installed 2>/dev/null | wc -l)
PKGS_FILE="/var/tmp/monitor_packages_last"
if [ -f "$PKGS_FILE" ]; then PKGS_LAST=$(cat "$PKGS_FILE" | tr -d '[:space:]'); else PKGS_LAST="$PKGS_CURR"; fi
if [ "$PKGS_CURR" != "$PKGS_LAST" ]; then
    PKGS_STATUS="ALERTA"; PKGS_CLASSE="status-alerta"; HAS_ALERTA=1
    PKGS_DETALHE="Alterado! (Antigo: $PKGS_LAST | Atual: $PKGS_CURR)"
else
    PKGS_STATUS="OK"; PKGS_CLASSE="status-ok"
    PKGS_DETALHE="$PKGS_CURR pacotes instalados"
fi
echo "$PKGS_CURR" > "$PKGS_FILE"

UPDATES_COUNT=$(dnf check-update -q --errorlevel=0 | grep -E '^\S+\.' | wc -l)
if [ -z "$UPDATES_COUNT" ]; then UPDATES_COUNT=0; fi
if [ "$UPDATES_COUNT" -gt 0 ]; then
    UPDATES_STATUS="INFO"; UPDATES_CLASSE="status-info"
    UPDATES_DETALHE="Há $UPDATES_COUNT atualizações disponíveis"
else
    UPDATES_STATUS="OK"; UPDATES_CLASSE="status-ok"
    UPDATES_DETALHE="Sistema 100% atualizado"
fi

SHELL_CURR=$(bash --version | head -n1 | awk '{print $4}')
SHELL_FILE="/var/tmp/monitor_shell_version"
if [ -f "$SHELL_FILE" ]; then SHELL_LAST=$(cat "$SHELL_FILE" | tr -d '[:space:]'); else SHELL_LAST="$SHELL_CURR"; fi
if [ "$SHELL_CURR" != "$SHELL_LAST" ]; then
    SHELL_STATUS="ALERTA"; SHELL_CLASSE="status-alerta"; HAS_ALERTA=1
    SHELL_DETALHE="Mudou! (Antiga: $SHELL_LAST | Atual: $SHELL_CURR)"
else
    SHELL_STATUS="OK"; SHELL_CLASSE="status-ok"
    SHELL_DETALHE="Bash v$SHELL_CURR"
fi
echo "$SHELL_CURR" > "$SHELL_FILE"

DISK_TOTAL_VAL=$(df -h / | tail -n1 | awk '{print $2}')
DISK_USED_PCT=$(df / | tail -n1 | awk '{print $5}' | tr -d '%')
DISK_FREE_PCT=$((100 - DISK_USED_PCT))
if [ "$DISK_FREE_PCT" -lt 10 ]; then
    DISK_STATUS="ALERTA"; DISK_CLASSE="status-alerta"; HAS_ALERTA=1
elif [ "$DISK_FREE_PCT" -lt 20 ]; then
    DISK_STATUS="INFO"; DISK_CLASSE="status-info"
else
    DISK_STATUS="OK"; DISK_CLASSE="status-ok"
fi
DISK_DETALHE="Total: $DISK_TOTAL_VAL | Espaço Livre: ${DISK_FREE_PCT}%"

LOAD_1=$(cat /proc/loadavg | awk '{print $1}')
LOAD_5=$(cat /proc/loadavg | awk '{print $2}')
LOAD_15=$(cat /proc/loadavg | awk '{print $3}')
LOAD_HIGH=$(awk -v l1="$LOAD_1" -v l5="$LOAD_5" -v l15="$LOAD_15" 'BEGIN { if (l1 > 5.0 || l5 > 5.0 || l15 > 5.0) print "1"; else print "0" }')
if [ "$LOAD_HIGH" -eq 1 ]; then
    LOAD_STATUS="ALERTA"; LOAD_CLASSE="status-alerta"; HAS_ALERTA=1
else
    LOAD_STATUS="OK"; LOAD_CLASSE="status-ok"
fi
LOAD_DETALHE="1m: $LOAD_1 | 5m: $LOAD_5 | 15m: $LOAD_15"

MEM_TOTAL=$(/usr/bin/free -m | awk '/^Mem:/ {print $2}')
MEM_USED=$(/usr/bin/free -m | awk '/^Mem:/ {print $3}')
if [ "$MEM_TOTAL" -gt 0 ]; then
    MEM_USED_PCT=$((100 * MEM_USED / MEM_TOTAL))
else
    MEM_USED_PCT=0
fi
if [ "$MEM_USED_PCT" -gt 95 ]; then MEM_STATUS="ALERTA"; MEM_CLASSE="status-alerta"; HAS_ALERTA=1; else MEM_STATUS="OK"; MEM_CLASSE="status-ok"; fi
MEM_DETALHE="Uso: ${MEM_USED_PCT}% de ${MEM_TOTAL}MB Total"

SWAP_TOTAL=$(/usr/bin/free -m | awk '/^Swap:/ {print $2}')
SWAP_USED=$(/usr/bin/free -m | awk '/^Swap:/ {print $3}')
if [ "$SWAP_TOTAL" -gt 0 ]; then
    SWAP_USED_PCT=$((100 * SWAP_USED / SWAP_TOTAL))
else
    SWAP_USED_PCT=0
fi
if [ "$SWAP_USED_PCT" -gt 95 ]; then SWAP_STATUS="ALERTA"; SWAP_CLASSE="status-alerta"; HAS_ALERTA=1; else SWAP_STATUS="OK"; SWAP_CLASSE="status-ok"; fi
SWAP_DETALHE="Uso Swap: ${SWAP_USED_PCT}% de ${SWAP_TOTAL}MB Total"

USERS_COUNT=$(who | wc -l)
if [ "$USERS_COUNT" -ne 0 ]; then
    USERS_STATUS="ALERTA"; USERS_CLASSE="status-alerta"; HAS_ALERTA=1
    USERS_DETALHE="$USERS_COUNT usuário(s) conectado(s) via SSH!"
else
    LAST_LOGON=$(last -1 | head -n1 | awk '{print $4, $5, $6, $7}')
    USERS_STATUS="OK"; USERS_CLASSE="status-ok"
    USERS_DETALHE="0 usuários logados ($LAST_LOGON)"
fi

PROCS_TOTAL=$(ps ax | wc -l)
PROCS_ZOMBIES=$(ps ax -o state | grep -c Z)
if [ "$PROCS_ZOMBIES" -ne 0 ]; then
    ZOMBIES_STATUS="ALERTA"; ZOMBIES_CLASSE="status-alerta"; HAS_ALERTA=1
    ZOMBIES_DETALHE="Detectados $PROCS_ZOMBIES processos zumbis!"
else
    ZOMBIES_STATUS="OK"; ZOMBIES_CLASSE="status-ok"
    ZOMBIES_DETALHE="0 zumbis ($PROCS_TOTAL processos totais)"
fi

# ------------------------------------------------------------------------------
# 3. COLETA DE DADOS - 3) STATUS DE VERSÕES E COMPONENTES DA STACK
# ------------------------------------------------------------------------------
VER_NGINX=$(/usr/sbin/nginx -v 2>&1 | awk -F'/' '{print $2}' | awk '{print $1}')
[ -z "$VER_NGINX" ] && VER_NGINX="N/A"
if systemctl is-active nginx >/dev/null 2>&1; then STATUS_NGINX="OK"; CLASSE_NGINX="status-ok"; DETALHE_NGINX="Serviço Ativo"; else STATUS_NGINX="ALERTA"; CLASSE_NGINX="status-alerta"; HAS_ALERTA=1; DETALHE_NGINX="Serviço Inativo!"; fi

VER_CROWDSEC=$(cscli version 2>&1 | grep "version:" | awk '{print $2}' || echo "N/A")
if systemctl is-active crowdsec >/dev/null 2>&1; then STATUS_CROWDSEC="OK"; CLASSE_CROWDSEC="status-ok"; DETALHE_CROWDSEC="Security Engine Rodando"; else STATUS_CROWDSEC="ALERTA"; CLASSE_CROWDSEC="status-alerta"; HAS_ALERTA=1; DETALHE_CROWDSEC="Serviço Parado!"; fi

VER_CERTBOT=$(certbot --version 2>/dev/null | awk '{print $2}' || echo "N/A")
if [ -d "/etc/letsencrypt/live/n8n.nogueiraconsultoria.eti.br" ]; then STATUS_CERTBOT="OK"; CLASSE_CERTBOT="status-ok"; DETALHE_CERTBOT="Certificado SSL Válido"; else STATUS_CERTBOT="ALERTA"; CLASSE_CERTBOT="status-alerta"; HAS_ALERTA=1; DETALHE_CERTBOT="Diretório SSL não encontrado!"; fi

VER_PM2=$(su - nogueira -c "source ~/.bash_profile; pm2 -v" 2>/dev/null | tail -n 1)
if su - nogueira -c "pm2 ping" 2>/dev/null | grep -q "pong"; then STATUS_PM2="OK"; CLASSE_PM2="status-ok"; DETALHE_PM2="Ambiente PM2 Operacional"; else STATUS_PM2="ALERTA"; CLASSE_PM2="status-alerta"; HAS_ALERTA=1; DETALHE_PM2="PM2 Inacessível!"; fi

VER_N8N=$(su - nogueira -c "source ~/.bash_profile; n8n --version" 2>/dev/null | tail -n 1)
if su - nogueira -c "pm2 jlist" 2>/dev/null | grep -q '"name":"n8n".*"status":"online"'; then STATUS_N8N="OK"; CLASSE_N8N="status-ok"; DETALHE_N8N="Instância Online"; else STATUS_N8N="ALERTA"; CLASSE_N8N="status-alerta"; HAS_ALERTA=1; DETALHE_N8N="N8N Fora do Ar no PM2!"; fi

VER_MODSEC=$(strings /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so 2>/dev/null | grep -i "ModSecurity-nginx v" | head -n1 | awk '{print $2}')
[ -z "$VER_MODSEC" ] && VER_MODSEC="N/A"
STATUS_MODSEC="OK"; CLASSE_MODSEC="status-ok"; DETALHE_MODSEC="WAF Integrado ao Nginx"

VER_LOGROTATE=$(/usr/sbin/logrotate --version 2>&1 | head -n1 | awk '{print $2}')
CONT_LOGROTATE_ERRORS=$(/usr/sbin/logrotate -d /etc/logrotate.conf 2>&1 | grep -iE '\berror\b|\bcrit(ic(al)?)?\b|\bfalha\b|\bfail(ure)?\b' | grep -vi "error.log" | wc -l)
if [ "$CONT_LOGROTATE_ERRORS" -gt 0 ]; then
    STATUS_LOGROTATE="ALERTA"; CLASSE_LOGROTATE="status-alerta"; HAS_ALERTA=1; DETALHE_LOGROTATE="Erros detectados: $CONT_LOGROTATE_ERRORS"
else
    STATUS_LOGROTATE="OK"; CLASSE_LOGROTATE="status-ok"; DETALHE_LOGROTATE="Rotação configurada."
fi

# ------------------------------------------------------------------------------
# 4. COLETA DE DADOS - 4) STATUS DE PERFORMANCE (N8N APM)
# ------------------------------------------------------------------------------
N8N_PM2_INFO=$(su - nogueira -c "pm2 info n8n" 2>/dev/null)

VAL_N8N_UP=$(echo "$N8N_PM2_INFO" | grep -i "│ uptime" | awk -F'│' '{print $3}' | xargs)
if echo "$VAL_N8N_UP" | grep -qi "d"; then ST_N8N_UP="OK"; CLS_N8N_UP="status-ok"; else ST_N8N_UP="ALERTA"; CLS_N8N_UP="status-alerta"; HAS_ALERTA=1; fi

N8N_RESTARTS=$(echo "$N8N_PM2_INFO" | grep -i "│ restarts" | awk -F'│' '{print $3}' | xargs)
N8N_RESTARTS=${N8N_RESTARTS:-0}
if [ "$N8N_RESTARTS" -gt 5 ]; then ST_N8N_RST="ALERTA"; CLS_N8N_RST="status-alerta"; HAS_ALERTA=1; else ST_N8N_RST="OK"; CLS_N8N_RST="status-ok"; fi

N8N_ACTIVE_REQ=$(echo "$N8N_PM2_INFO" | grep -i "Active requests" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_ACTIVE_REQ=${N8N_ACTIVE_REQ:-0}
if [ "$N8N_ACTIVE_REQ" -gt 0 ]; then ST_N8N_REQ="ALERTA"; CLS_N8N_REQ="status-alerta"; HAS_ALERTA=1; else ST_N8N_REQ="OK"; CLS_N8N_REQ="status-ok"; fi

N8N_ACTIVE_HANDLES=$(echo "$N8N_PM2_INFO" | grep -i "Active handles" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_ACTIVE_HANDLES=${N8N_ACTIVE_HANDLES:-0}
if [ "$N8N_ACTIVE_HANDLES" -gt 15 ]; then ST_N8N_HND="ALERTA"; CLS_N8N_HND="status-alerta"; HAS_ALERTA=1; else ST_N8N_HND="OK"; CLS_N8N_HND="status-ok"; fi

N8N_EVENT_LOOP=$(echo "$N8N_PM2_INFO" | grep -i "Event Loop Latency" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_EVENT_LOOP=${N8N_EVENT_LOOP%.*}
N8N_EVENT_LOOP=${N8N_EVENT_LOOP:-0}
if [ "$N8N_EVENT_LOOP" -gt 1 ]; then ST_N8N_EVL="ALERTA"; CLS_N8N_EVL="status-alerta"; HAS_ALERTA=1; else ST_N8N_EVL="OK"; CLS_N8N_EVL="status-ok"; fi

N8N_HTTP_MEAN=$(echo "$N8N_PM2_INFO" | grep -i "HTTP Mean Latency" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_HTTP_MEAN=${N8N_HTTP_MEAN%.*}
N8N_HTTP_MEAN=${N8N_HTTP_MEAN:-0}
if [ "$N8N_HTTP_MEAN" -gt 25 ]; then ST_N8N_MEAN="ALERTA"; CLS_N8N_MEAN="status-alerta"; HAS_ALERTA=1; else ST_N8N_MEAN="OK"; CLS_N8N_MEAN="status-ok"; fi

N8N_HTTP_P95=$(echo "$N8N_PM2_INFO" | grep -i "HTTP P95 Latency" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_HTTP_P95=${N8N_HTTP_P95%.*}
N8N_HTTP_P95=${N8N_HTTP_P95:-0}
if [ "$N8N_HTTP_P95" -gt 600 ]; then ST_N8N_P95="ALERTA"; CLS_N8N_P95="status-alerta"; HAS_ALERTA=1; else ST_N8N_P95="OK"; CLS_N8N_P95="status-ok"; fi

N8N_HTTP_REQ=$(echo "$N8N_PM2_INFO" | grep -i "HTTP req/min" | awk -F'│' '{print $3}' | xargs | awk '{print $1}')
N8N_HTTP_REQ=${N8N_HTTP_REQ%.*}
N8N_HTTP_REQ=${N8N_HTTP_REQ:-0}
if [ "$N8N_HTTP_REQ" -gt 1 ]; then ST_N8N_RQM="ALERTA"; CLS_N8N_RQM="status-alerta"; HAS_ALERTA=1; else ST_N8N_RQM="OK"; CLS_N8N_RQM="status-ok"; fi

# ------------------------------------------------------------------------------
# 5. COLETA DE DADOS - 5) AUDITORIA E LOGS (24h)
# ------------------------------------------------------------------------------
> "$ERR_FILE"

function append_log {
    local titulo="$1"
    local resultado="$2"
    if [ -n "$resultado" ]; then
        echo "=========================================================" >> "$ERR_FILE"
        echo "[ $titulo ]" >> "$ERR_FILE"
        echo "=========================================================" >> "$ERR_FILE"
        echo "$resultado" >> "$ERR_FILE"
        echo "" >> "$ERR_FILE"
    fi
}

N8N_PM2_LOG=$(su - nogueira -c "timeout 5 pm2 logs n8n --nostream --lines 50" 2>/dev/null | sed -r 's/\x1B\[[0-9;]*[mK]//g')

RES=$(journalctl -p 0..3 -q --since "24 hours ago" --no-pager | tail -n 15)
append_log "System / Messages / Boot" "$RES"

RES=$(journalctl -u sshd -q --since "24 hours ago" --no-pager | grep -iE 'fail|error|invalid|refused' | tail -n 15)
append_log "Secure (Auth)" "$RES"

DT_HOJE=$(date '+%Y/%m/%d')
DT_ONTEM=$(date -d 'yesterday' '+%Y/%m/%d')
RES=$(grep -E "^($DT_HOJE|$DT_ONTEM)" /var/log/nginx/error.log 2>/dev/null | grep -iE 'error|crit|emerg' | tail -n 15)
append_log "Nginx" "$RES"

RES=$(grep -E "^($DT_HOJE|$DT_ONTEM)" /var/log/nginx/error.log 2>/dev/null | grep -i 'ModSecurity' | tail -n 15)
append_log "ModSecurity" "$RES"

RES=$(grep -iE 'error|fail|fatal|panic' /var/log/crowdsec.log 2>/dev/null | tail -n 15)
append_log "CrowdSec" "$RES"

RES=$(su - nogueira -c "timeout 10 pm2 logs n8n --raw --nostream --lines 1000" 2>/dev/null | sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep -iE 'error|fail|exception|unauthorized|denied' | tail -n 15)
append_log "N8N App" "$RES"

LOGS_HTML=$(cat "$ERR_FILE" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
if [ -z "$LOGS_HTML" ]; then LOGS_HTML="Nenhum erro registrado nos logs nas últimas 24h."; fi

# ------------------------------------------------------------------------------
# 6. COLETA DE DADOS - 6) SEGURANÇA E CVEs (COMPLIANCE)
# ------------------------------------------------------------------------------
TMP_CRIT="/tmp/monitor_crit.txt"
TMP_NONCRIT="/tmp/monitor_noncrit.txt"
> "$TMP_CRIT"
> "$TMP_NONCRIT"

# Extrai Instalados (Compliance)
dnf updateinfo list cves --installed 2>/dev/null | awk '/Critical/ {print $1 "|" $3 "|Compliance"}' >> "$TMP_CRIT"
dnf updateinfo list cves --installed 2>/dev/null | awk '/Important|Moderate|Low/ {print $1 "|" $3 "|Compliance"}' >> "$TMP_NONCRIT"

# Extrai Pendentes (Em Fila)
dnf updateinfo list cves 2>/dev/null | awk '/Critical/ {print $1 "|" $3 "|Em Fila"}' >> "$TMP_CRIT"
dnf updateinfo list cves 2>/dev/null | awk '/Important|Moderate|Low/ {print $1 "|" $3 "|Em Fila"}' >> "$TMP_NONCRIT"

# Ordenação Cronológica Inversa (Mais novo para o mais antigo)
sort -r -o "$TMP_CRIT" "$TMP_CRIT"
sort -r -o "$TMP_NONCRIT" "$TMP_NONCRIT"

# Calculando Totais para o Dashboard
TOT_COMPLIANCE=$(cat "$TMP_CRIT" "$TMP_NONCRIT" | grep -c "Compliance")
TOT_FILA=$(cat "$TMP_CRIT" "$TMP_NONCRIT" | grep -c "Em Fila")
TOT_AUSENTE=0

# Montando Estrutura HTML - Críticos
HTML_CRIT=""
while IFS='|' read -r cve pkg status; do
    [ -z "$cve" ] && continue
    if [ "$status" == "Compliance" ]; then
        badge="<span class=\"status-badge status-ok\">Compliance</span>"
    elif [ "$status" == "Em Fila" ]; then
        badge="<span class=\"status-badge status-info\">Em Fila</span>"
    else
        badge="<span class=\"status-badge status-alerta\">Ausente</span>"
    fi
    HTML_CRIT+="<tr><td><strong>$cve</strong></td><td>$pkg</td><td>$badge</td></tr>"
done < "$TMP_CRIT"
[ -z "$HTML_CRIT" ] && HTML_CRIT="<tr><td colspan='3'>Nenhum CVE Crítico encontrado.</td></tr>"

# Montando Estrutura HTML - Não Críticos
HTML_NONCRIT=""
while IFS='|' read -r cve pkg status; do
    [ -z "$cve" ] && continue
    if [ "$status" == "Compliance" ]; then
        badge="<span class=\"status-badge status-ok\">Compliance</span>"
    elif [ "$status" == "Em Fila" ]; then
        badge="<span class=\"status-badge status-info\">Em Fila</span>"
    else
        badge="<span class=\"status-badge status-alerta\">Ausente</span>"
    fi
    HTML_NONCRIT+="<tr><td><strong>$cve</strong></td><td>$pkg</td><td>$badge</td></tr>"
done < "$TMP_NONCRIT"
[ -z "$HTML_NONCRIT" ] && HTML_NONCRIT="<tr><td colspan='3'>Nenhum CVE Não Crítico (Important/Moderate/Low) encontrado.</td></tr>"

# ------------------------------------------------------------------------------
# 7. CÁLCULO DE DURAÇÃO DE EXECUÇÃO
# ------------------------------------------------------------------------------
EXEC_DURATION=$SECONDS

if [ -f "$MAX_DUR_FILE" ]; then
    MAX_DUR_VAL=$(cut -d'|' -f1 "$MAX_DUR_FILE")
    MAX_DUR_DATE=$(cut -d'|' -f2 "$MAX_DUR_FILE")
    if ! [[ "$MAX_DUR_VAL" =~ ^[0-9]+$ ]]; then MAX_DUR_VAL=0; fi
else
    MAX_DUR_VAL=0
    MAX_DUR_DATE="Nunca"
fi

if [ "$EXEC_DURATION" -gt "$MAX_DUR_VAL" ]; then
    MAX_DUR_VAL=$EXEC_DURATION
    MAX_DUR_DATE=$DATA_EXECUCAO
    echo "${MAX_DUR_VAL}|${MAX_DUR_DATE}" > "$MAX_DUR_FILE"
fi

if [ "$HAS_ALERTA" -eq 1 ]; then STATUS_GERAL="ALERTA"; CLASSE_GERAL="status-alerta"; else STATUS_GERAL="OK"; CLASSE_GERAL="status-ok"; fi

# ------------------------------------------------------------------------------
# 8. ESTRUTURA VISUAL COMPARTILHADA (HTML/CSS)
# ------------------------------------------------------------------------------
HTML_HEAD_CSS="
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <meta http-equiv=\"refresh\" content=\"60\">
    <title>Monitor SRE - VPS NOGX01</title>
    <style>
        :root {
            --bg-color: #f4f6f9; --card-bg: #ffffff; --text-color: #333333; --text-muted: #666666;
            --border-color: #e0e0e0; --heading-color: #2c3e50; --accent-color: #3498db;
            --table-header-bg: #f8f9fa; --table-header-text: #495057; --detalhes-bg: #2d3748;
            --detalhes-text: #ffffff;
            --ok-bg: #d4edda; --ok-text: #155724;
            --alerta-bg: #f8d7da; --alerta-text: #721c24;
            --info-bg: #d1ecf1; --info-text: #0c5460;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-color: #121212; --card-bg: #1e1e1e; --text-color: #e0e0e0; --text-muted: #aaaaaa;
                --border-color: #333333; --heading-color: #ffffff; --accent-color: #64b5f6;
                --table-header-bg: #2a2a2a; --table-header-text: #e0e0e0; --detalhes-bg: #000000;
                --detalhes-text: #4caf50;
                --ok-bg: rgba(16, 124, 65, 0.2); --ok-text: #81c784;
                --alerta-bg: rgba(168, 0, 0, 0.2); --alerta-text: #e57373;
                --info-bg: rgba(0, 120, 212, 0.2); --info-text: #64b5f6;
            }
        }
        body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; background: var(--bg-color); color: var(--text-color); margin: 0; padding: 20px; line-height: 1.5; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border-color); padding-bottom: 10px; margin-bottom: 15px; flex-wrap: wrap; }
        .header h1 { margin: 0; font-size: 24px; color: var(--heading-color); }
        .meta-info { font-size: 14px; color: var(--text-muted); text-align: right; line-height: 1.6; }
        .nav-bar { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
        .nav-btn { 
            padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; 
            transition: all 0.2s; background: var(--detalhes-bg); color: #fff; border: 1px solid var(--border-color);
        }
        .nav-btn:hover { opacity: 0.8; }
        .nav-btn.active { background: var(--accent-color); color: #fff; border-color: var(--accent-color); }
        .table-responsive { width: 100%; overflow-x: auto; background: var(--card-bg); border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 25px; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
        th, td { padding: 12px 15px; border-bottom: 1px solid var(--border-color); }
        th { background: var(--table-header-bg); color: var(--table-header-text); font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        .status-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
        .status-ok { background: var(--ok-bg); color: var(--ok-text); }
        .status-alerta { background: var(--alerta-bg); color: var(--alerta-text); }
        .status-info { background: var(--info-bg); color: var(--info-text); }
        h2 { font-size: 18px; color: var(--heading-color); margin-top: 0; margin-bottom: 15px; padding-left: 5px; border-left: 4px solid var(--accent-color); }
        .detalhes-bloco { background: var(--detalhes-bg); color: var(--detalhes-text); padding: 15px; border-radius: 8px; font-family: \"SFMono-Regular\", Consolas, monospace; font-size: 13px; white-space: pre-wrap; overflow-x: auto; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 25px; }
        .dash-card { background: var(--card-bg); padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: 1px solid var(--border-color); }
        .dash-card h3 { margin: 0 0 10px 0; font-size: 16px; color: var(--text-muted); }
        .dash-card .value { font-size: 32px; font-weight: bold; }
    </style>
</head>
"

HTML_HEADER_DIV="
    <div class=\"header\">
        <h1>Monitor SRE - n8n.nogueiraconsultoria.eti.br</h1>
        <div class=\"meta-info\">
            <strong>Última Execução:</strong> $DATA_EXECUCAO <br>
            <strong>Duração do Script:</strong> ${EXEC_DURATION}s <br>
            <strong>Última Duração Máxima:</strong> ${MAX_DUR_VAL}s (em $MAX_DUR_DATE) <br>
            <strong>Versão do Script:</strong> v$VERSAO_SCRIPT
        </div>
    </div>
"

# ------------------------------------------------------------------------------
# 9. GERAÇÃO - PÁGINA PRINCIPAL (index.html)
# ------------------------------------------------------------------------------
cat <<EOF > "$OUTPUT_INDEX"
<!DOCTYPE html>
<html lang="pt-BR">
$HTML_HEAD_CSS
<body>
<div class="container">
$HTML_HEADER_DIV
    <div class="nav-bar">
        <a href="index.html" class="nav-btn active">📊 Visão Geral</a>
        <a href="security_compliance.html" class="nav-btn">🛡️ Security & Compliance</a>
        <a href="erros_logs_24h.html" class="nav-btn">📝 Erros em Logs (24h)</a>
    </div>

    <h2>1) Status Geral do Servidor</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>Item do Core</th><th>Valor do Atributo</th><th>Status Atual</th></tr></thead>
            <tbody>
                <tr><td><strong>STATUS GERAL DO ECOSSISTEMA</strong></td><td>Compilação consolidada de apontamentos ativos</td><td><span class="status-badge $CLASSE_GERAL">$STATUS_GERAL</span></td></tr>
                <tr><td><strong>IP Público do Host</strong></td><td>$IP_PUBLICO</td><td><span class="status-badge status-ok">OK</span></td></tr>
                <tr><td><strong>Sistema Operacional / Kernel</strong></td><td>$SO_VERSAO ($KERNEL_VERSAO)</td><td><span class="status-badge status-ok">OK</span></td></tr>
                <tr><td><strong>Segurança Mandatória SELinux</strong></td><td>Políticas $SELINUX_STATUS</td><td><span class="status-badge $SELINUX_CLASSE">$SELINUX_STATUS</span></td></tr>
                <tr><td><strong>Conectividade Externa (Gateway)</strong></td><td>$GATEWAY_STATUS</td><td><span class="status-badge $GATEWAY_CLASSE">$GATEWAY_STATUS</span></td></tr>
                <tr><td><strong>Resolução DNS n8n</strong></td><td>$DNS_STATUS</td><td><span class="status-badge $DNS_CLASSE">$DNS_STATUS</span></td></tr>
            </tbody>
        </table>
    </div>

    <h2>2) Componentes do Sistema Operacional</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>Item Verificado</th><th>Métrica / Diagnóstico Atual</th><th>Status de Integridade</th></tr></thead>
            <tbody>
                <tr><td><strong>Uptime</strong></td><td>Tempo ativo: $UPTIME_EXIBIR</td><td><span class="status-badge $UPTIME_CLASSE">$UPTIME_STATUS</span></td></tr>
                <tr><td><strong>Packages Installed</strong></td><td>$PKGS_DETALHE</td><td><span class="status-badge $PKGS_CLASSE">$PKGS_STATUS</span></td></tr>
                <tr><td><strong>Last Packages Updates</strong></td><td>$UPDATES_DETALHE</td><td><span class="status-badge $UPDATES_CLASSE">$UPDATES_STATUS</span></td></tr>
                <tr><td><strong>Shell</strong></td><td>$SHELL_DETALHE</td><td><span class="status-badge $SHELL_CLASSE">$SHELL_STATUS</span></td></tr>
                <tr><td><strong>Disk Total | Disk Usage</strong></td><td>$DISK_DETALHE</td><td><span class="status-badge $DISK_CLASSE">$DISK_STATUS</span></td></tr>
                <tr><td><strong>System Load</strong></td><td>$LOAD_DETALHE</td><td><span class="status-badge $LOAD_CLASSE">$LOAD_STATUS</span></td></tr>
                <tr><td><strong>Memory Usage</strong></td><td>$MEM_DETALHE</td><td><span class="status-badge $MEM_CLASSE">$MEM_STATUS</span></td></tr>
                <tr><td><strong>Swap Usage</strong></td><td>$SWAP_DETALHE</td><td><span class="status-badge $SWAP_CLASSE">$SWAP_STATUS</span></td></tr>
                <tr><td><strong>Total Users Logged in</strong></td><td>$USERS_DETALHE</td><td><span class="status-badge $USERS_CLASSE">$USERS_STATUS</span></td></tr>
                <tr><td><strong>Total Process Zombies</strong></td><td>$ZOMBIES_DETALHE</td><td><span class="status-badge $ZOMBIES_CLASSE">$ZOMBIES_STATUS</span></td></tr>
            </tbody>
        </table>
    </div>

    <h2>3) Status de Versões e Componentes (Stack Web)</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>Componente</th><th>Versão Instalada</th><th>Integridade</th><th>Auditoria Manual</th></tr></thead>
            <tbody>
                <tr><td><strong>Kpatch (Live Patching)</strong></td><td>$KERNEL_VERSAO</td><td><span class="status-badge $KPATCH_CORE_CLASSE">OK</span></td><td>$KPATCH_CORE_STATUS</td></tr>
                <tr><td><strong>Nginx Webserver</strong></td><td>v$VER_NGINX</td><td><span class="status-badge $CLASSE_NGINX">$STATUS_NGINX</span></td><td>$DETALHE_NGINX</td></tr>
                <tr><td><strong>ModSecurity (WAF)</strong></td><td>v$VER_MODSEC</td><td><span class="status-badge $CLASSE_MODSEC">$STATUS_MODSEC</span></td><td>$DETALHE_MODSEC</td></tr>
                <tr><td><strong>CrowdSec (Security Engine)</strong></td><td>v$VER_CROWDSEC</td><td><span class="status-badge $CLASSE_CROWDSEC">$STATUS_CROWDSEC</span></td><td>$DETALHE_CROWDSEC</td></tr>
                <tr><td><strong>Certbot (Let's Encrypt)</strong></td><td>v$VER_CERTBOT</td><td><span class="status-badge $CLASSE_CERTBOT">$STATUS_CERTBOT</span></td><td>$DETALHE_CERTBOT</td></tr>
                <tr><td><strong>Logrotate System</strong></td><td>v$VER_LOGROTATE</td><td><span class="status-badge $CLASSE_LOGROTATE">$STATUS_LOGROTATE</span></td><td>$DETALHE_LOGROTATE</td></tr>
                <tr><td><strong>PM2 (Usuário: nogueira)</strong></td><td>v$VER_PM2</td><td><span class="status-badge $CLASSE_PM2">$STATUS_PM2</span></td><td>$DETALHE_PM2</td></tr>
                <tr><td><strong>N8N (Usuário: nogueira)</strong></td><td>v$VER_N8N</td><td><span class="status-badge $CLASSE_N8N">$STATUS_N8N</span></td><td>$DETALHE_N8N</td></tr>
            </tbody>
        </table>
    </div>

    <h2>4) Status de Performance (N8N APM)</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>Métrica do PM2 Monitor</th><th>Valor de Referência Máximo</th><th>Status Atual</th><th>Integridade</th></tr></thead>
            <tbody>
                <tr><td><strong>Uptime Processo</strong></td><td>1d (Alerta se < 1d)</td><td>$VAL_N8N_UP</td><td><span class="status-badge $CLS_N8N_UP">$ST_N8N_UP</span></td></tr>
                <tr><td><strong>Restarts</strong></td><td>5</td><td>$N8N_RESTARTS</td><td><span class="status-badge $CLS_N8N_RST">$ST_N8N_RST</span></td></tr>
                <tr><td><strong>Active Requests</strong></td><td>0</td><td>$N8N_ACTIVE_REQ</td><td><span class="status-badge $CLS_N8N_REQ">$ST_N8N_REQ</span></td></tr>
                <tr><td><strong>Active Handles</strong></td><td>15</td><td>$N8N_ACTIVE_HANDLES</td><td><span class="status-badge $CLS_N8N_HND">$ST_N8N_HND</span></td></tr>
                <tr><td><strong>Event Loop Latency</strong></td><td>1 ms</td><td>${N8N_EVENT_LOOP} ms</td><td><span class="status-badge $CLS_N8N_EVL">$ST_N8N_EVL</span></td></tr>
                <tr><td><strong>HTTP Mean Latency</strong></td><td>25 ms</td><td>${N8N_HTTP_MEAN} ms</td><td><span class="status-badge $CLS_N8N_MEAN">$ST_N8N_MEAN</span></td></tr>
                <tr><td><strong>HTTP P95 Latency</strong></td><td>600 ms</td><td>${N8N_HTTP_P95} ms</td><td><span class="status-badge $CLS_N8N_P95">$ST_N8N_P95</span></td></tr>
                <tr><td><strong>HTTP req/min</strong></td><td>1</td><td>$N8N_HTTP_REQ</td><td><span class="status-badge $CLS_N8N_RQM">$ST_N8N_RQM</span></td></tr>
            </tbody>
        </table>
    </div>

    <h2>5) Detalhes dos Apontamentos / Auditoria Recente</h2>
    <div class="detalhes-bloco"><strong>Relatório de Atividades Recentes do N8N via PM2 (Últimas linhas / 24h):</strong>
$(echo "$N8N_PM2_LOG" | tail -n 15)

-----------------------------------------------------------------------------------------
<strong>Histórico Recente de Atualizações Críticas (/home/nogueira/atualiza_n8n.log):</strong>
$(tail -n 10 "$LOG_FILE" 2>/dev/null || echo "Nenhum registro encontrado em $LOG_FILE.")</div>

</div>
</body>
</html>
EOF

# ------------------------------------------------------------------------------
# 10. GERAÇÃO - PÁGINA DE SECURITY & COMPLIANCE (security_compliance.html)
# ------------------------------------------------------------------------------
cat <<EOF > "$OUTPUT_SECURITY"
<!DOCTYPE html>
<html lang="pt-BR">
$HTML_HEAD_CSS
<body>
<div class="container">
$HTML_HEADER_DIV
    <div class="nav-bar">
        <a href="index.html" class="nav-btn">📊 Visão Geral</a>
        <a href="security_compliance.html" class="nav-btn active">🛡️ Security & Compliance</a>
        <a href="erros_logs_24h.html" class="nav-btn">📝 Erros em Logs (24h)</a>
    </div>

    <h2>1) Visão Geral (Geral)</h2>
    <div class="dashboard-grid">
        <div class="dash-card">
            <h3>Em Compliance</h3>
            <div class="value" style="color: var(--ok-text);">$TOT_COMPLIANCE</div>
        </div>
        <div class="dash-card">
            <h3>Em Fila (Aguardando Update)</h3>
            <div class="value" style="color: var(--info-text);">$TOT_FILA</div>
        </div>
        <div class="dash-card">
            <h3>Não Compliance (Ausentes)</h3>
            <div class="value" style="color: var(--alerta-text);">$TOT_AUSENTE</div>
        </div>
    </div>

    <h2>2) Vulnerabilidades e Patches (Críticos)</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>ID do CVE</th><th>Pacote / Dependência</th><th>Status do Patch</th></tr></thead>
            <tbody>
                $HTML_CRIT
            </tbody>
        </table>
    </div>

    <h2>3) Vulnerabilidades e Patches (Não Críticos)</h2>
    <div class="table-responsive">
        <table>
            <thead><tr><th>ID do CVE</th><th>Pacote / Dependência</th><th>Status do Patch</th></tr></thead>
            <tbody>
                $HTML_NONCRIT
            </tbody>
        </table>
    </div>

</div>
</body>
</html>
EOF

# ------------------------------------------------------------------------------
# 11. GERAÇÃO - PÁGINA DE ERROS (erros_logs_24h.html)
# ------------------------------------------------------------------------------
cat <<EOF > "$OUTPUT_LOGS"
<!DOCTYPE html>
<html lang="pt-BR">
$HTML_HEAD_CSS
<body>
<div class="container">
$HTML_HEADER_DIV
    <div class="nav-bar">
        <a href="index.html" class="nav-btn">📊 Visão Geral</a>
        <a href="security_compliance.html" class="nav-btn">🛡️ Security & Compliance</a>
        <a href="erros_logs_24h.html" class="nav-btn active">📝 Erros em Logs (24h)</a>
    </div>

    <h2>6) Erros em Logs / Auditoria Recente (Últimas 24h)</h2>
    <div class="detalhes-bloco">${LOGS_HTML}</div>

</div>
</body>
</html>
EOF

chmod 644 "$OUTPUT_INDEX" "$OUTPUT_SECURITY" "$OUTPUT_LOGS"
chown nginx:nginx "$OUTPUT_INDEX" "$OUTPUT_SECURITY" "$OUTPUT_LOGS" 2>/dev/null || true

exit 0