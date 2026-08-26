import re
import math
import base64
import urllib.parse
import ipaddress
import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Analyst Toolkit | CTRDEFENSE.BLOG",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# DESIGN SYSTEM: CSS CYBERPUNK / GLASSMORPHISM & JAVASCRIPT
# -----------------------------------------------------------------------------
st.markdown("""
    <style>
        /* Importação de fontes High-Tech */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            background-color: #050811;
            color: #cbd5e1;
        }

        /* Fundo Dinâmico com Gradiante Cyber */
        .stApp {
            background: radial-gradient(circle at 50% -20%, #0f172a, #050811, #020408);
        }

        /* Estilização do Cabeçalho Principal */
        .main-header {
            font-family: 'JetBrains Mono', monospace;
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(90deg, #00f2fe 0%, #4facfe 50%, #00c6ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -1px;
            margin-bottom: 0px;
            text-shadow: 0 0 20px rgba(0, 242, 254, 0.2);
        }

        .sub-header {
            font-size: 0.95rem;
            color: #64748b;
            margin-bottom: 20px;
        }

        /* Cards de Links de Threat Intel (Glassmorphism) */
        .tool-card {
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(51, 65, 85, 0.5);
            backdrop-filter: blur(12px);
            border-radius: 10px;
            padding: 14px 18px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none !important;
            display: block;
            margin-bottom: 10px;
        }

        .tool-card:hover {
            border-color: #00f2fe;
            transform: translateY(-3px);
            box-shadow: 0 8px 20px -6px rgba(0, 242, 254, 0.3);
        }

        .tool-title {
            font-family: 'JetBrains Mono', monospace;
            color: #38bdf8;
            font-weight: 600;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tool-desc {
            color: #94a3b8;
            font-size: 0.8rem;
            margin-top: 4px;
        }

        /* Customização das Abas (Tabs) */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            background-color: rgba(15, 23, 42, 0.8);
            padding: 6px;
            border-radius: 10px;
            border: 1px solid #1e293b;
        }

        .stTabs [data-baseweb="tab"] {
            font-family: 'JetBrains Mono', monospace;
            background-color: transparent;
            border-radius: 6px;
            padding: 8px 16px;
            color: #64748b;
            font-size: 0.85rem;
            border: none !important;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
            color: #00f2fe !important;
            box-shadow: 0 0 10px rgba(0, 242, 254, 0.15);
            border: 1px solid rgba(0, 242, 254, 0.3) !important;
        }

        /* Customização de Metricas */
        [data-testid="stMetricValue"] {
            font-family: 'JetBrains Mono', monospace;
            color: #00f2fe !important;
        }

        /* Rodapé Cyber */
        .footer-text {
            text-align: center;
            padding: 20px;
            color: #475569;
            font-size: 0.85rem;
            border-top: 1px solid #1e293b;
            margin-top: 50px;
            font-family: 'JetBrains Mono', monospace;
        }
    </style>

    <!-- Injeção de JS para copiar elementos para área de transferência se necessário -->
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text);
        }
    </script>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# HEADER DA APLICAÇÃO
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ SOC ANALYST TOOLKIT</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Platform Architecture for Threat Intelligence, Detection Engineering & Incident Response</div>', unsafe_allow_html=True)

VT_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")

# -----------------------------------------------------------------------------
# HUB DE FERRAMENTAS RÁPIDAS (SOC & THREAT INTEL)
# -----------------------------------------------------------------------------
with st.expander("🔗 **Quick-Access Threat Intel & Investigation Hub**", expanded=True):
    col_link1, col_link2, col_link3, col_link4, col_link5 = st.columns(5)
    
    with col_link1:
        st.markdown("""
            <a href="https://www.phishtool.com/" target="_blank" class="tool-card">
                <div class="tool-title">📧 PhishTool</div>
                <div class="tool-desc">Análise forense e triagem técnica de e-mails maliciosos.</div>
            </a>
        """, unsafe_allow_html=True)

    with col_link2:
        st.markdown("""
            <a href="https://bazaar.abuse.ch/" target="_blank" class="tool-card">
                <div class="tool-title">☣️ MalwareBazaar</div>
                <div class="tool-desc">Repositório aberto para amostragem de amostras de malware.</div>
            </a>
        """, unsafe_allow_html=True)

    with col_link3:
        st.markdown("""
            <a href="https://www.shodan.io/" target="_blank" class="tool-card">
                <div class="tool-title">🌐 Shodan</div>
                <div class="tool-desc">Mapeamento de ativos de rede e inteligência de exposição.</div>
            </a>
        """, unsafe_allow_html=True)

    with col_link4:
        st.markdown("""
            <a href="https://www.verexif.com/" target="_blank" class="tool-card">
                <div class="tool-title">📷 VerExif Online</div>
                <div class="tool-desc">Extração de metadados ocultos em arquivos de imagem.</div>
            </a>
        """, unsafe_allow_html=True)

    with col_link5:
        st.markdown("""
            <a href="https://mxtoolbox.com/" target="_blank" class="tool-card">
                <div class="tool-title">🛠️ MXToolbox</div>
                <div class="tool-desc">Diagnóstico de registros DNS, MX, SPF, DKIM e Blacklists.</div>
            </a>
        """, unsafe_allow_html=True)

st.divider()

# -----------------------------------------------------------------------------
# ENRIQUECIMENTO VIRUSTOTAL V3 API
# -----------------------------------------------------------------------------
def get_vt_data(endpoint, item_id):
    if not VT_API_KEY or VT_API_KEY == "sua_chave_api_do_virustotal_aqui":
        return {"error": "Chave API não configurada"}

    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{item_id}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Não encontrado no VT"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def parse_vt_details(vt_response):
    if "error" in vt_response:
        return {"verdict": f"⚠️ {vt_response['error']}", "score": "N/A", "detalhes": "N/D", "tags": "N/A"}
    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        tags = attrs.get("tags", [])[:3]

        verdict = f"🚨 Malicioso ({malicious}/{total})" if malicious > 0 else f"✅ Limpo ({stats.get('harmless', 0)}/{total})"
        return {"verdict": verdict, "score": attrs.get("reputation", 0), "detalhes": f"Malicioso: {malicious}", "tags": ", ".join(tags) if tags else "Sem Tags"}
    except KeyError:
        return {"verdict": "Erro na estrutura", "score": "N/A", "detalhes": "N/D", "tags": "N/D"}

# Initial State
if "last_analyzed_text" not in st.session_state:
    st.session_state["last_analyzed_text"] = ""

# -----------------------------------------------------------------------------
# NAVEGAÇÃO DE ABAS
# -----------------------------------------------------------------------------
tab_iocs, tab_mitre, tab_queries, tab_entropy, tab_email, tab_decoder, tab_ps_deobf, tab_network = st.tabs([
    "🔍 Extrator & VT",
    "🥷 MITRE ATT&CK",
    "🎯 SIEM/EDR Queries",
    "📊 Entropia",
    "📧 Analisador E-mail",
    "🔓 Decodificador",
    "⚔️ PS Deobfuscator",
    "🌐 IPs & CIDR"
])

# =============================================================================
# ABA 1: EXTRATOR & VIRUSTOTAL
# =============================================================================
with tab_iocs:
    st.header("🔍 Extrator de IOCs & Reputação Threat Intel")
    raw_text = st.text_area("Cole os logs, e-mails ou payloads aqui para análise:", height=150, placeholder="Ex: 192.168.1.1, powershell.exe -enc ..., http://badsite.com")

    def extract_iocs(text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        return list(set(re.findall(ip_pattern, text))), list(set(re.findall(url_pattern, text))), list(set(re.findall(md5_pattern, text))), list(set(re.findall(sha256_pattern, text)))

    if st.button("Executar Triagem do Artefato", type="primary"):
        st.session_state["last_analyzed_text"] = raw_text
        ips, urls, md5s, sha256s = extract_iocs(raw_text)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IPs Encontrados", len(ips))
        c2.metric("URLs Mapeadas", len(urls))
        c3.metric("Hashes MD5", len(md5s))
        c4.metric("Hashes SHA256", len(sha256s))

        st.divider()
        all_hashes = md5s + sha256s
        if all_hashes:
            st.subheader("🧩 Hashes de Artefatos")
            hash_data = []
            for h in all_hashes:
                vt_info = parse_vt_details(get_vt_data("files", h))
                hash_data.append({"Hash": h, "Tipo": "SHA256" if len(h) == 64 else "MD5", "Veredito VT": vt_info["verdict"], "Score": vt_info["score"], "Tags": vt_info["tags"], "Link VirusTotal": f"https://www.virustotal.com/gui/file/{h}"})
            st.dataframe(pd.DataFrame(hash_data), column_config={"Link VirusTotal": st.column_config.LinkColumn("VirusTotal", display_text="Abrir VT ↗")}, use_container_width=True, hide_index=True)

        if ips:
            st.subheader("🌐 Endereços IP")
            ip_data = []
            for ip in ips:
                vt_info = parse_vt_details(get_vt_data("ip_addresses", ip))
                ip_data.append({"IP": ip, "Veredito VT": vt_info["verdict"], "Link VT": f"https://www.virustotal.com/gui/ip-address/{ip}", "Link AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}"})
            st.dataframe(pd.DataFrame(ip_data), column_config={"Link VT": st.column_config.LinkColumn("VT ↗"), "Link AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB ↗")}, use_container_width=True, hide_index=True)

# =============================================================================
# ABA 2: NOVO - MAPEADOR DINÂMICO MITRE ATT&CK
# =============================================================================
with tab_mitre:
    st.header("🥷 Mapeamento Dinâmico de TTPs (MITRE ATT&CK Matrix)")
    st.caption("Identificação automática de Táticas, Técnicas e Procedimentos (TTPs) extraídas do comportamento do payload analisado.")

    target_text = st.session_state.get("last_analyzed_text", "")

    def map_mitre_ttps(text):
        ttps = []
        patterns = [
            (r'powershell|pwsh|-enc|-encodedcommand', 'Execution', 'Command and Scripting Interpreter: PowerShell', 'T1059.001', 'Uso do PowerShell para execução de scripts arbitrários.'),
            (r'cmd\.exe|/c|/k', 'Execution', 'Command and Scripting Interpreter: Windows Command Shell', 'T1059.003', 'Execução de comandos via Windows Command Shell.'),
            (r'reg add|HKLM|HKCU|CurrentVersion\\Run', 'Persistence', 'Boot or Logon Autostart Execution: Registry Run Keys', 'T1547.001', 'Modificação de chaves do registro para persistência.'),
            (r'lsass|mimikatz|sekurlsa|sekurlsa::logonpasswords', 'Credential Access', 'OS Credential Dumping: LSASS Memory', 'T1003.001', 'Tentativa de extração de credenciais diretamente da memória do LSASS.'),
            (r'bitsadmin|certutil|curl|wget', 'Defense Evasion', 'Ingress Tool Transfer', 'T1105', 'Uso de utilitários nativos para download de artefatos maliciosos.'),
            (r'schtasks|taskengine', 'Persistence', 'Scheduled Task/Job: Scheduled Task', 'T1053.005', 'Criação ou alteração de tarefas agendadas no SO.'),
            (r'vssadmin|delete shadows|wmic shadowcopy delete', 'Impact', 'Inhibit System Recovery', 'T1490', 'Tentativa de exclusão de Shadow Copies para impedir recuperação (Típico de Ransomware).'),
            (r'https?://[^\s<>"]+', 'Command and Control', 'Application Layer Protocol: Web Protocols', 'T1071.001', 'Uso de protocolos HTTP/HTTPS para comunicação C2.'),
            (r'base64|frombase64string', 'Defense Evasion', 'Deobfuscate/Decode Files or Information', 'T1140', 'Decodificação de payloads obfuscados em memória.')
        ]

        for pat, tactic, technique, tech_id, desc in patterns:
            if re.search(pat, text, re.IGNORECASE):
                ttps.append({
                    "Tática MITRE": tactic,
                    "ID Técnica": tech_id,
                    "Nome da Técnica": technique,
                    "Descrição & Contexto": desc,
                    "Referência MITRE": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                })
        return ttps

    if not target_text.strip():
        st.info("💡 Nenhuma análise em memória. Insira um texto/log na aba '🔍 Extrator & VT' para mapear as TTPs automaticamente.")
    else:
        detected_ttps = map_mitre_ttps(target_text)
        if detected_ttps:
            st.success(f"🎯 Identificadas {len(detected_ttps)} TTPs no comportamento do artefato:")
            df_mitre = pd.DataFrame(detected_ttps)
            st.dataframe(
                df_mitre,
                column_config={
                    "Referência MITRE": st.column_config.LinkColumn("MITRE ATT&CK ↗", display_text="Abrir Matriz ↗")
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.warning("Nenhum padrão comportamento evidente mapeado na base atual do MITRE para o texto informado.")

# =============================================================================
# ABA 3: THREAT HUNTING QUERY BUILDER
# =============================================================================
with tab_queries:
    st.header("🎯 Threat Hunting Query Builder")
    col_q1, col_q2 = st.columns([1, 2])
    with col_q1:
        ioc_type = st.selectbox("Tipo de Artefato:", ["Endereço IP", "Hash SHA256/MD5", "Nome do Processo"])
        ioc_values = st.text_area("Insira os indicadores (um por linha):", height=120)
    with col_q2:
        siem_platform = st.radio("Plataforma:", ["Microsoft Sentinel (KQL)", "Elasticsearch (EQL)", "CrowdStrike Falcon"], horizontal=True)
        if st.button("Gerar Query"):
            items = [item.strip() for item in ioc_values.splitlines() if item.strip()]
            if items:
                if siem_platform == "Microsoft Sentinel (KQL)":
                    q = f"DeviceNetworkEvents | where RemoteIP in ({', '.join([f'\"{i}\"' for i in items])})"
                elif siem_platform == "Elasticsearch (EQL)":
                    q = f"network where destination.ip in ({', '.join([f'\"{i}\"' for i in items])})"
                else:
                    q = f"event_simpleName=NetworkConnectIP4 (" + " OR ".join([f'RemoteAddressIP4="{i}"' for i in items]) + ")"
                st.code(q, language="sql")

# =============================================================================
# ABA 4: CALCULADOR DE ENTROPIA
# =============================================================================
with tab_entropy:
    st.header("📊 Calculador de Entropia de Shannon")
    raw_str = st.text_area("Insira a String/Payload Base64 para cálculo de aleatoriedade:", height=100)
    if raw_str:
        try:
            b_data = base64.b64decode(raw_str.strip())
        except Exception:
            b_data = raw_str.encode('utf-8')
        
        counts = [0] * 256
        for b in b_data: counts[b] += 1
        entropy = -sum((c / len(b_data)) * math.log2(c / len(b_data)) for c in counts if c > 0)
        
        st.metric("Score de Entropia", f"{entropy:.4f} / 8.0")
        if entropy > 7.1:
            st.error("🚨 Altíssima Entropia: Forte indício de obfuscação, packing ou criptografia.")
        else:
            st.success("🟢 Entropia Normal: Padrão dentro do esperado para código não empacotado.")

# =============================================================================
# ABA 5: ANALISADOR DE E-MAIL
# =============================================================================
with tab_email:
    st.header("📧 Analisador de Cabeçalhos de E-mail")
    raw_header = st.text_area("Cole o cabeçalho bruto (Raw Header):", height=150)
    if st.button("Analisar Registros"):
        spf = re.search(r'spf=(\w+)', raw_header, re.I)
        dkim = re.search(r'dkim=(\w+)', raw_header, re.I)
        dmarc = re.search(r'dmarc=(\w+)', raw_header, re.I)
        c1, c2, c3 = st.columns(3)
        c1.metric("SPF", spf.group(1).upper() if spf else "N/A")
        c2.metric("DKIM", dkim.group(1).upper() if dkim else "N/A")
        c3.metric("DMARC", dmarc.group(1).upper() if dmarc else "N/A")

# =============================================================================
# ABA 6: DECODIFICADOR
# =============================================================================
with tab_decoder:
    st.header("🔓 Decodificador Genérico")
    enc_str = st.text_input("String obfuscada:")
    if enc_str:
        st.text_input("URL Decoded:", urllib.parse.unquote(enc_str))
        try:
            st.text_area("Base64 Decoded:", base64.b64decode(enc_str).decode('utf-8', errors='ignore'))
        except Exception:
            pass

# =============================================================================
# ABA 7: POWERSHELL DEOBFUSCATOR
# =============================================================================
with tab_ps_deobf:
    st.header("⚔️ PowerShell Deobfuscator")
    ps_script = st.text_area("Script / Comando PowerShell Obfuscado:", height=120)
    if st.button("Desobfuscar"):
        cleaned = ps_script.replace("`", "").replace("^", "")
        cleaned = re.sub(r"['\"](?:\s*\+\s*)['\"]", "", cleaned)
        st.code(cleaned, language="powershell")

# =============================================================================
# ABA 8: IPS & CIDR
# =============================================================================
with tab_network:
    st.header("🌐 Calculadora CIDR & Análise de IPs")
    ip_in = st.text_input("IP para verificação de escopo:", value="10.0.0.1")
    if ip_in:
        try:
            ip_o = ipaddress.ip_address(ip_in)
            st.info(f"O IP `{ip_in}` é **{'PRIVADO (RFC 1918)' if ip_o.is_private else 'PÚBLICO / INTERNET'}**.")
        except ValueError:
            st.error("IP Inválido.")

# -----------------------------------------------------------------------------
# RODAPÉ
# -----------------------------------------------------------------------------
st.markdown("""
    <div class="footer-text">
        CTRDEFENSE.BLOG &copy; 2026 | Enterprise Cyber Security & Threat Intelligence Suite
    </div>
""", unsafe_allow_html=True)
