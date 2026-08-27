import re
import math
import base64
import urllib.parse
import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# 1. CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Cyber Threat Research - Caçador de Ameaças V2beta",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 2. DESIGN SYSTEM: CSS CYBERPUNK / GLASSMORPHISM
# -----------------------------------------------------------------------------
st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            background-color: #050811;
            color: #cbd5e1;
        }

        .stApp {
            background: radial-gradient(circle at 50% -20%, #0f172a, #050811, #020408);
        }

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

        .tool-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 10px;
        }

        .tool-card {
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(51, 65, 85, 0.5);
            backdrop-filter: blur(12px);
            border-radius: 10px;
            padding: 14px 18px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none !important;
            display: block;
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

        [data-testid="stMetricValue"] {
            font-family: 'JetBrains Mono', monospace;
            color: #00f2fe !important;
        }

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
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 3. GERENCIAMENTO SEGURO DAS API KEYS NA SIDEBAR
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔑 Credenciais API")
    
    def_vt = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    def_abuse = st.secrets.get("ABUSEIPDB_API_KEY", "")
    def_urlscan = st.secrets.get("URLSCAN_API_KEY", "")
    def_greynoise = st.secrets.get("GREYNOISE_API_KEY", "")

    user_vt_key = st.text_input("VirusTotal API Key:", value=st.session_state.get("vt_key_input", def_vt), type="password", key="vt_key_input")
    user_abuse_key = st.text_input("AbuseIPDB API Key:", value=st.session_state.get("abuse_key_input", def_abuse), type="password", key="abuse_key_input")
    user_urlscan_key = st.text_input("urlscan.io API Key:", value=st.session_state.get("urlscan_key_input", def_urlscan), type="password", key="urlscan_key_input")
    user_greynoise_key = st.text_input("GreyNoise API Key (Business/Enterprise):", value=st.session_state.get("greynoise_key_input", def_greynoise), type="password", key="greynoise_key_input")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("💾 Salvar", use_container_width=True):
            st.session_state["active_vt_key"] = user_vt_key
            st.session_state["active_abuse_key"] = user_abuse_key
            st.session_state["active_urlscan_key"] = user_urlscan_key
            st.session_state["active_greynoise_key"] = user_greynoise_key
            st.success("Salvas!")
            st.rerun()

    with col_btn2:
        if st.button("🗑️ Limpar", use_container_width=True):
            for k in ["vt_key_input", "abuse_key_input", "urlscan_key_input", "greynoise_key_input",
                      "active_vt_key", "active_abuse_key", "active_urlscan_key", "active_greynoise_key"]:
                st.session_state[k] = ""
            st.warning("Removidas!")
            st.rerun()

    st.divider()

VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", def_vt))
ABUSE_API_KEY = st.session_state.get("active_abuse_key", st.session_state.get("abuse_key_input", def_abuse))
URLSCAN_API_KEY = st.session_state.get("active_urlscan_key", st.session_state.get("urlscan_key_input", def_urlscan))
GREYNOISE_API_KEY = st.session_state.get("active_greynoise_key", st.session_state.get("greynoise_key_input", def_greynoise))

# -----------------------------------------------------------------------------
# 4. HEADER DA APLICAÇÃO & STATUS DA API
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Cyber Threat Research - Caçador de Ameaças V2b</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Threat Hunting, Detection Engineering & Dynamic Threat Mapping</div>', unsafe_allow_html=True)

status_cols = st.columns(5)
status_cols[0].caption("🟢 VT" if VT_API_KEY else "🔴 VT")
status_cols[1].caption("🟢 AbuseIPDB" if ABUSE_API_KEY else "🔴 AbuseIPDB")
status_cols[2].caption("🟢 urlscan" if URLSCAN_API_KEY else "🔴 urlscan")
status_cols[3].caption("🟢 GreyNoise (Business)" if GREYNOISE_API_KEY else "🟡 GreyNoise (Public)")
status_cols[4].caption("🟢 XposedOrNot (Free)")

# -----------------------------------------------------------------------------
# 5. QUICK-ACCESS THREAT INTEL HUB (ÚNICO MARKDOWN)
# -----------------------------------------------------------------------------
with st.expander("🔗 **Quick-Access Threat Intel & Investigation Hub**", expanded=False):
    st.markdown("""
        <div class="tool-grid">
            <a href="https://www.phishtool.com/" target="_blank" class="tool-card">
                <div class="tool-title">📧 PhishTool</div>
                <div class="tool-desc">Triagem de e-mails maliciosos.</div>
            </a>
            <a href="https://bazaar.abuse.ch/" target="_blank" class="tool-card">
                <div class="tool-title">☣️ MalwareBazaar</div>
                <div class="tool-desc">Amostras abertas de malware.</div>
            </a>
            <a href="https://www.hybrid-analysis.com/" target="_blank" class="tool-card">
                <div class="tool-title">🔬 Hybrid Analysis</div>
                <div class="tool-desc">Sandbox dinâmica gratuita.</div>
            </a>
            <a href="https://www.shodan.io/" target="_blank" class="tool-card">
                <div class="tool-title">🌐 Shodan</div>
                <div class="tool-desc">Exposição de serviços de rede.</div>
            </a>
            <a href="https://www.verexif.com/" target="_blank" class="tool-card">
                <div class="tool-title">📷 VerExif Online</div>
                <div class="tool-desc">Metadados de imagem.</div>
            </a>
            <a href="https://mxtoolbox.com/" target="_blank" class="tool-card">
                <div class="tool-title">🛠️ MXToolbox</div>
                <div class="tool-desc">Análise DNS, MX, SPF, DKIM.</div>
            </a>
        </div>
    """, unsafe_allow_html=True)

st.divider()

# -----------------------------------------------------------------------------
# 6. MÓDULOS DE INTEGRAÇÃO COM APIS EXTERNAS
# -----------------------------------------------------------------------------

# --- VirusTotal ---
def get_vt_data(endpoint, item_id):
    if not VT_API_KEY:
        return {"error": "Chave API não configurada"}
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{item_id}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Não encontrado no VT"}
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def parse_vt_details(vt_response):
    if "error" in vt_response:
        return {"verdict": f"⚠️ {vt_response['error']}", "score": "N/A", "tags": "N/A", "file_name": "N/D", "file_type": "N/D", "file_size": "N/D"}
    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        tags = attrs.get("tags", [])[:3]
        meaningful_name = attrs.get("meaningful_name", "")
        names_list = attrs.get("names", [])
        primary_name = meaningful_name if meaningful_name else (names_list[0] if names_list else "Desconhecido")
        file_type = attrs.get("type_description", attrs.get("magic", "N/D"))
        file_size = attrs.get("size", "N/D")
        verdict = f"🚨 Malicioso ({malicious}/{total})" if malicious > 0 else f"✅ Limpo ({stats.get('harmless', 0)}/{total})"
        return {"verdict": verdict, "score": attrs.get("reputation", 0), "tags": ", ".join(tags) if tags else "Sem Tags", "file_name": primary_name, "file_type": file_type, "file_size": f"{file_size:,} bytes" if isinstance(file_size, int) else file_size}
    except KeyError:
        return {"verdict": "Erro na estrutura", "score": "N/A", "tags": "N/D", "file_name": "N/D", "file_type": "N/D", "file_size": "N/D"}

# --- AbuseIPDB ---
def check_abuseipdb(ip_address):
    if not ABUSE_API_KEY:
        return {"error": "Sem API Key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            return {"score": f"{data['abuseConfidenceScore']}%", "reports": data["totalReports"], "country": data["countryCode"], "isp": data["isp"]}
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# --- GreyNoise (Comunitário e Enterprise/Business) ---
def check_greynoise(ip_address):
    if GREYNOISE_API_KEY:
        url = f"https://api.greynoise.io/v3/noise/context/{ip_address}"
        headers = {"Accept": "application/json", "key": GREYNOISE_API_KEY}
    else:
        url = f"https://api.greynoise.io/v3/community/{ip_address}"
        headers = {"Accept": "application/json"}

    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            return {"message": "IP não catalogado como ruído generalizado no GreyNoise."}
        elif res.status_code == 401:
            return {"error": "Chave API do GreyNoise inválida ou sem permissão."}
        elif res.status_code == 429:
            return {"error": "Limite de requisições atingido no GreyNoise."}
        elif res.status_code == 410:
            return {"error": "Erro 410: O endpoint utilizado foi descontinuado pela GreyNoise."}
        return {"error": f"HTTP {res.status_code}: {res.text}"}
    except Exception as e:
        return {"error": str(e)}

# --- urlscan.io ---
def submit_urlscan(target_url):
    if not URLSCAN_API_KEY:
        return {"error": "Sem API Key"}
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": target_url, "visibility": "public"}
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return response.json()
        return {"error": f"HTTP {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

# --- XposedOrNot Analytics ---
def check_xposedornot_analytics(email):
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            return {"status": "clean", "Error": "Not found"}
        return {"error": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# -----------------------------------------------------------------------------
# 7. NAVEGAÇÃO POR ABAS OPERACIONAIS
# -----------------------------------------------------------------------------
tab_iocs, tab_hypotheses, tab_queries, tab_urlscan, tab_greynoise, tab_entropy, tab_email, tab_xposed = st.tabs([
    "🔍 Extrator & AbuseIP",
    "🎯 Central de Hipóteses",
    "🎯 SIEM Queries",
    "🌐 urlscan.io",
    "📡 GreyNoise",
    "📊 Entropia",
    "📧 Cabeçalho E-mail",
    "🔓 XposedOrNot"
])

# =============================================================================
# ABA 1: EXTRATOR, VIRUSTOTAL & ABUSEIPDB
# =============================================================================
with tab_iocs:
    st.header("🔍 Extrator de IOCs + AbuseIP")
    raw_text = st.text_area("Cole os IOCs para análise e banimentos (IP, Domain, MD5, SHA256):", height=120)

    def extract_iocs(text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        return list(set(re.findall(ip_pattern, text))), list(set(re.findall(url_pattern, text))), list(set(re.findall(md5_pattern, text))), list(set(re.findall(sha256_pattern, text)))

    if st.button("Executar Triagem Multiferramenta", type="primary"):
        ips, urls, md5s, sha256s = extract_iocs(raw_text)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IPs Encontrados", len(ips))
        c2.metric("URLs Mapeadas", len(urls))
        c3.metric("Hashes MD5", len(md5s))
        c4.metric("Hashes SHA256", len(sha256s))

        st.divider()
        all_hashes = md5s + sha256s
        if all_hashes:
            st.subheader("🧩 Hashes (VirusTotal & Hybrid Analysis)")
            hash_data = []
            for h in all_hashes:
                vt_info = parse_vt_details(get_vt_data("files", h))
                hash_data.append({
                    "Hash": h,
                    "Nome": vt_info["file_name"],
                    "Tipo": vt_info["file_type"],
                    "Tamanho": vt_info["file_size"],
                    "Veredito VT": vt_info["verdict"],
                    "Score VT": vt_info["score"],
                    "Tags": vt_info["tags"],
                    "Link VT": f"https://www.virustotal.com/gui/file/{h}",
                    "Link HA": f"https://www.hybrid-analysis.com/search?query={h}"
                })
            st.dataframe(pd.DataFrame(hash_data), column_config={"Link VT": st.column_config.LinkColumn("VT ↗"), "Link HA": st.column_config.LinkColumn("HA ↗")}, use_container_width=True, hide_index=True)

        if ips:
            st.subheader("🌐 Endereços IP (VirusTotal + AbuseIPDB)")
            ip_data = []
            for ip in ips:
                vt_info = parse_vt_details(get_vt_data("ip_addresses", ip))
                abuse_info = check_abuseipdb(ip)
                
                score_abuse = abuse_info.get("score", "N/A") if isinstance(abuse_info, dict) else "N/A"
                isp_info = abuse_info.get("isp", "N/A") if isinstance(abuse_info, dict) else "N/A"

                ip_data.append({
                    "IP": ip,
                    "Veredito VT": vt_info["verdict"],
                    "Abuse Score": score_abuse,
                    "ISP": isp_info,
                    "Link VT": f"https://www.virustotal.com/gui/ip-address/{ip}",
                    "Link AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}"
                })
            st.dataframe(pd.DataFrame(ip_data), column_config={"Link VT": st.column_config.LinkColumn("VT ↗"), "Link AbuseIPDB": st.column_config.LinkColumn("AbuseIPDB ↗")}, use_container_width=True, hide_index=True)

# =============================================================================
# ABA 2: CENTRAL DE HIPÓTESES DE THREAT HUNTING
# =============================================================================
with tab_hypotheses:
    st.header("🎯 Central de Hipóteses de Threat Hunting")
    st.caption("Cadastre e gerencie hipóteses de caça baseadas no framework MITRE ATT&CK.")
    
    if "hypotheses_db" not in st.session_state:
        st.session_state["hypotheses_db"] = []

    with st.form("form_hypothesis", clear_on_submit=True):
        col_h1, col_h2 = st.columns(2)
        with col_h1:
            h_title = st.text_input("Título da Hipótese:", placeholder="Ex: Execução de PowerShell codificado via WMI")
            h_tactic = st.selectbox("Tática MITRE ATT&CK:", [
                "TA0001 - Initial Access", "TA0002 - Execution", "TA0003 - Persistence",
                "TA0004 - Privilege Escalation", "TA0005 - Defense Evasion", "TA0006 - Credential Access",
                "TA0007 - Discovery", "TA0008 - Lateral Movement", "TA0009 - Collection",
                "TA0011 - Command and Control", "TA0010 - Exfiltration", "TA0040 - Impact"
            ])
        with col_h2:
            h_datasources = st.text_input("Fontes de Dados (Data Sources):", placeholder="Ex: Sysmon Event ID 1, Windows Security 4688, EDR")
            h_status = st.selectbox("Status da Investigação:", ["Em Rascunho", "Em Validação", "Confirmado (Incident)", "Falso Positivo", "Concluído"])

        h_desc = st.text_area("Descrição Breve / Rationale:", placeholder="Explique o comportamento esperado do atacante e os indicadores esperados...")
        
        btn_add = st.form_submit_button("➕ Registrar Hipótese", type="primary")

        if btn_add:
            if h_title and h_desc:
                st.session_state["hypotheses_db"].append({
                    "Título": h_title,
                    "Tática": h_tactic,
                    "Data Sources": h_datasources,
                    "Status": h_status,
                    "Descrição": h_desc
                })
                st.success("Hipótese adicionada com sucesso!")
            else:
                st.error("Por favor, preencha pelo menos o Título e a Descrição.")

    st.divider()
    hyp_list = st.session_state["hypotheses_db"]
    st.subheader(f"📋 Hipóteses Registradas ({len(hyp_list)})")
    
    if hyp_list:
        st.dataframe(pd.DataFrame(hyp_list), use_container_width=True)
        if st.button("🗑️ Limpar Todas as Hipóteses"):
            st.session_state["hypotheses_db"] = []
            st.rerun()
    else:
        st.info("Nenhuma hipótese cadastrada até o momento.")

# =============================================================================
# ABA 3: SIEM QUERIES
# =============================================================================
with tab_queries:
    st.header("🎯 Threat Hunting Query Builder")
    col_q1, col_q2 = st.columns([1, 2])
    with col_q1:
        ioc_values = st.text_area("Insira os indicadores:", height=120)
    with col_q2:
        siem_platform = st.radio("Plataforma:", ["Microsoft Sentinel (KQL)", "Elasticsearch (EQL)", "CrowdStrike Falcon"], horizontal=True)
        if st.button("Gerar Query"):
            items = [item.strip() for item in ioc_values.splitlines() if item.strip()]
            if items:
                q = f"DeviceNetworkEvents | where RemoteIP in ({', '.join([f'\"{i}\"' for i in items])})" if "Sentinel" in siem_platform else f"network where destination.ip in ({items})"
                st.code(q, language="sql")

# =============================================================================
# ABA 4: URLSCAN.IO
# =============================================================================
with tab_urlscan:
    st.header("🌐 urlscan.io - Análise de URLs")
    st.caption("Submeta URLs suspeitas para verificação dinâmica, requisições HTTP e screenshots.")
    
    target_scan_url = st.text_input("Insira a URL suspeita:", placeholder="https://exemplo-phishing.com")
    if st.button("🚀 Enviar para urlscan.io", type="primary"):
        if target_scan_url:
            res = submit_urlscan(target_scan_url)
            if "error" in res:
                st.error(res["error"])
            else:
                st.success("Submissão realizada com sucesso!")
                st.json(res)
                if "result" in res:
                    st.markdown(f"🔗 [Clique aqui para acompanhar o resultado completo no urlscan.io]({res['result']})")

# =============================================================================
# ABA 5: GREYNOISE (MODO BUSINESS / ENTERPRISE)
# =============================================================================
with tab_greynoise:
    st.header("📡 GreyNoise - Filtro de Ruído da Internet")
    st.caption("Descubra se o IP examinado é um scanner inofensivo conhecido, botnet ou IP malicioso.")
    
    if not GREYNOISE_API_KEY:
        st.info("ℹ️ **Modo Comunitário Gratuito Ativo:** Exibindo dados básicos. Adicione uma API Key na barra lateral para habilitar todos os campos enriquecidos.")
    else:
        st.success("🔑 **Modo Autenticado Business/Enterprise Ativo:** Trazendo contexto completo de inteligência.")

    gn_ip = st.text_input("Insira o endereço IP para consulta no GreyNoise:", placeholder="8.8.8.8", key="gn_ip_input")
    if st.button("Consultar GreyNoise", type="primary"):
        if gn_ip:
            with st.spinner("Consultando GreyNoise..."):
                gn_res = check_greynoise(gn_ip)
                if "error" in gn_res:
                    st.error(gn_res["error"])
                elif "message" in gn_res:
                    st.warning(gn_res["message"])
                else:
                    st.subheader("📊 Classificação e Resumo")
                    col1, col2, col3 = st.columns(3)
                    
                    classification = str(gn_res.get("classification", "Desconhecido")).upper()
                    noise = gn_res.get("noise", gn_res.get("seen", False))
                    riot = gn_res.get("riot", False)

                    col1.metric("Classification", classification)
                    col2.metric("Noise (Scanner)", "Sim" if noise else "Não")
                    col3.metric("RIOT (Confiável)", "Sim" if riot else "Não")

                    st.markdown("### 📋 Detalhes Avançados do IP")
                    
                    actor = gn_res.get("actor", gn_res.get("name", "Desconhecido"))
                    last_seen = gn_res.get("last_seen", "Desconhecido")
                    
                    metadata = gn_res.get("metadata", {})
                    organization = metadata.get("organization", gn_res.get("organization", "Desconhecido / Requer API Key"))
                    country = metadata.get("country", gn_res.get("country", gn_res.get("country_code", "Desconhecido")))
                    asn = metadata.get("asn", gn_res.get("asn", "Desconhecido"))
                    
                    st.markdown(f"**👤 Actor:** `{actor}`")
                    st.markdown(f"**🏢 Organization:** `{organization}`")
                    st.markdown(f"**🌍 Source Country:** `{country}`")
                    st.markdown(f"**⏳ Last Seen:** `{last_seen}`")
                    st.markdown(f"**🌐 ASN:** `{asn}`")
                    
                    raw_tags = gn_res.get("tags", [])
                    if raw_tags:
                        st.markdown("**🏷️ Tags Associadas:**")
                        tags_list = raw_tags if isinstance(raw_tags, list) else [raw_tags]
                        tags_html = "".join([f"<span style='background-color:#1e293b; border: 1px solid #38bdf8; padding: 4px 8px; border-radius: 4px; margin-right: 6px; font-family: monospace; font-size: 0.85em;'>{t}</span>" for t in tags_list])
                        st.markdown(tags_html, unsafe_allow_html=True)

                    cves = gn_res.get("cve", [])
                    if cves:
                        st.markdown(f"**⚠️ CVEs Exploradas:** `{', '.join(cves)}`")

                    st.write("---")
                    gn_link = gn_res.get("link", f"https://viz.greynoise.io/ip/{gn_ip}")
                    st.markdown(f"🔗 [Visualizar no GreyNoise Viz]({gn_link})")

# =============================================================================
# ABA 6: CALCULADOR DE ENTROPIA
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

# =============================================================================
# ABA 7: ANALISADOR DE CABEÇALHO DE E-MAIL
# =============================================================================
with tab_email:
    st.header("📧 Analisador de Cabeçalho de E-mail")
    st.caption("Insira os cabeçalhos brutos de um e-mail para verificar a autenticidade dos registros SPF e DKIM.")
    
    raw_header = st.text_area("Cole o cabeçalho bruto (Raw Header):", height=200)
    if st.button("Analisar Registros DNS/SPF"):
        if raw_header:
            spf = re.search(r'spf=(\w+)', raw_header, re.I)
            dkim = re.search(r'dkim=(\w+)', raw_header, re.I)
            c1, c2 = st.columns(2)
            c1.metric("Status SPF", spf.group(1).upper() if spf else "N/A")
            c2.metric("Status DKIM", dkim.group(1).upper() if dkim else "N/A")

# =============================================================================
# ABA 8: CONSULTA DE VAZAMENTOS (XPOSEDORNOT)
# =============================================================================
with tab_xposed:
    st.header("🔓 Checar Vazamentos de E-mail (XposedOrNot)")
    st.caption("Consulte credenciais expostas e vazamentos públicos de dados sem a necessidade de chave de API.")

    target_email = st.text_input("Endereço de e-mail para investigação:", placeholder="usuario@empresa.com", key="xon_email_input")
    
    if st.button("🔍 Verificar Vazamentos", type="primary"):
        if target_email:
            with st.spinner("Consultando base de dados do XposedOrNot..."):
                res = check_xposedornot_analytics(target_email)
                
                if "error" in res:
                    st.error(f"Erro na consulta: {res['error']}")
                elif res.get("Error") == "Not found" or res.get("status") == "clean":
                    st.success("✅ **Nenhum vazamento encontrado para esta conta!**")
                else:
                    raw_breaches = res.get("ExposedBreaches", [])
                    if isinstance(raw_breaches, dict):
                        breaches_list = raw_breaches.get("breaches_details", raw_breaches.get("breaches", []))
                    elif isinstance(raw_breaches, list):
                        breaches_list = raw_breaches
                    else:
                        breaches_list = []

                    total_breaches = len(breaches_list)
                    
                    m1, m2 = st.columns(2)
                    m1.metric("Total de Vazamentos", total_breaches)
                    m2.metric("Status da Conta", "🚨 EXPOSTA" if total_breaches > 0 else "✅ SEGURA")

                    if total_breaches > 0:
                        st.subheader("📅 Detalhamento dos Vazamentos Encontrados")
                        
                        table_rows = []
                        for b in breaches_list:
                            if isinstance(b, dict):
                                name = b.get("breach", "N/A")
                                date_raw = b.get("xposed_date", b.get("breach_date", "Data desconhecida"))
                                industry = b.get("domain", "N/A")
                                records = b.get("xposed_records", 0)
                                data_types = b.get("xposed_data", "N/A")
                            else:
                                name = str(b)
                                date_raw, industry, records, data_types = "N/A", "N/A", "N/A", "N/A"

                            table_rows.append({
                                "Data / Ano": date_raw,
                                "Serviço / Fonte": name,
                                "Domínio": industry,
                                "Registros Expostos": f"{records:,}" if isinstance(records, int) else records,
                                "Dados Comprometidos": data_types
                            })

                        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

                        st.subheader("📝 Detalhes e Descrições dos Incidentes")
                        for b in breaches_list:
                            if isinstance(b, dict):
                                name = b.get("breach", "Desconhecido")
                                date_raw = b.get("xposed_date", "N/A")
                                details = b.get("details", "Sem detalhes adicionais disponíveis.")
                                st.markdown(f"- **{name}** ({date_raw}): {details}")

# =============================================================================
# ABA 9: CRUZAMENTO DE INTELIGÊNCIA (CROSS-INTEL)
# =============================================================================
with tab_cross_intel:
    st.header("🔗 Cruzamento de Inteligência (IP)")
    st.caption("Consulte simultaneamente VirusTotal, AbuseIPDB e GreyNoise para obter um contexto unificado da ameaça.")
    
    cross_ip = st.text_input("Insira o Endereço IP para correlação:", placeholder="1.1.1.1", key="cross_ip_input")
    
    if st.button("🚀 Iniciar Correlação", type="primary"):
        if cross_ip:
            with st.spinner("Consultando múltiplas fontes de inteligência..."):
                vt_res = parse_vt_details(get_vt_data("ip_addresses", cross_ip))
                abuse_res = check_abuseipdb(cross_ip)
                gn_res = check_greynoise(cross_ip)

                st.subheader("🎯 Resultado Consolidado")
                
                vt_verdict = vt_res.get("verdict", "N/A")
                
                abuse_score = abuse_res.get("score", "N/A") if isinstance(abuse_res, dict) else "Erro"
                abuse_isp = abuse_res.get("isp", "N/A") if isinstance(abuse_res, dict) else "N/A"
                
                if "error" in gn_res:
                    gn_class = f"Erro: {gn_res['error']}"
                    gn_actor = "N/A"
                elif "message" in gn_res:
                    gn_class = "Não Catalogado (Limpo/Desconhecido)"
                    gn_actor = "N/A"
                else:
                    gn_class = str(gn_res.get("classification", "Desconhecido")).upper()
                    gn_actor = gn_res.get("actor", gn_res.get("name", "Desconhecido"))

                col_c1, col_c2, col_c3 = st.columns(3)
                col_c1.info(f"**VirusTotal**\n\nVeredito: {vt_verdict}")
                col_c2.warning(f"**AbuseIPDB**\n\nScore de Abuso: {abuse_score}\n\nISP: {abuse_isp}")
                col_c3.error(f"**GreyNoise**\n\nClassificação: {gn_class}\n\nAtor: {gn_actor}")

                st.markdown("### 📋 Tabela de Atributos Cruzados")
                cross_data = {
                    "Fonte": ["VirusTotal", "AbuseIPDB", "GreyNoise"],
                    "Indicador Principal": [vt_verdict, abuse_score, gn_class],
                    "Contexto Adicional": [
                        vt_res.get("tags", "Sem tags"),
                        abuse_isp,
                        gn_actor
                    ]
                }
                st.dataframe(pd.DataFrame(cross_data), use_container_width=True, hide_index=True)
                
                st.markdown(f"""
                <div style="display: flex; gap: 10px; margin-top: 15px;">
                    <a href="https://www.virustotal.com/gui/ip-address/{cross_ip}" target="_blank" style="text-decoration:none;"><button style="cursor:pointer; padding:6px 12px; border-radius:5px; border:1px solid #38bdf8; background:transparent; color:#38bdf8;">Abrir no VirusTotal</button></a>
                    <a href="https://www.abuseipdb.com/check/{cross_ip}" target="_blank" style="text-decoration:none;"><button style="cursor:pointer; padding:6px 12px; border-radius:5px; border:1px solid #38bdf8; background:transparent; color:#38bdf8;">Abrir no AbuseIPDB</button></a>
                    <a href="https://viz.greynoise.io/ip/{cross_ip}" target="_blank" style="text-decoration:none;"><button style="cursor:pointer; padding:6px 12px; border-radius:5px; border:1px solid #38bdf8; background:transparent; color:#38bdf8;">Abrir no GreyNoise</button></a>
                </div>
                """, unsafe_allow_html=True)
