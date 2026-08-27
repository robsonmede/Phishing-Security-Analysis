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
    page_title="Cyber Threat Research - Caçador de Ameaças V1.5",
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
    st.markdown("### 🔑 Credenciais Threat Intel")
    
    # Defaults do secrets.toml se existirem
    def_vt = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    def_abuse = st.secrets.get("ABUSEIPDB_API_KEY", "")
    def_urlscan = st.secrets.get("URLSCAN_API_KEY", "")
    def_greynoise = st.secrets.get("GREYNOISE_API_KEY", "")
    def_hibp = st.secrets.get("HIBP_API_KEY", "")

    user_vt_key = st.text_input("VirusTotal API Key:", value=st.session_state.get("vt_key_input", def_vt), type="password", key="vt_key_input")
    user_abuse_key = st.text_input("AbuseIPDB API Key:", value=st.session_state.get("abuse_key_input", def_abuse), type="password", key="abuse_key_input")
    user_urlscan_key = st.text_input("urlscan.io API Key:", value=st.session_state.get("urlscan_key_input", def_urlscan), type="password", key="urlscan_key_input")
    user_greynoise_key = st.text_input("GreyNoise API Key:", value=st.session_state.get("greynoise_key_input", def_greynoise), type="password", key="greynoise_key_input")
    user_hibp_key = st.text_input("HIBP API Key:", value=st.session_state.get("hibp_key_input", def_hibp), type="password", key="hibp_key_input")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("💾 Salvar", use_container_width=True):
            st.session_state["active_vt_key"] = user_vt_key
            st.session_state["active_abuse_key"] = user_abuse_key
            st.session_state["active_urlscan_key"] = user_urlscan_key
            st.session_state["active_greynoise_key"] = user_greynoise_key
            st.session_state["active_hibp_key"] = user_hibp_key
            st.success("Salvas!")
            st.rerun()

    with col_btn2:
        if st.button("🗑️ Limpar", use_container_width=True):
            for k in ["vt_key_input", "abuse_key_input", "urlscan_key_input", "greynoise_key_input", "hibp_key_input",
                      "active_vt_key", "active_abuse_key", "active_urlscan_key", "active_greynoise_key", "active_hibp_key"]:
                st.session_state[k] = ""
            st.warning("Removidas!")
            st.rerun()

    st.divider()

VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", def_vt))
ABUSE_API_KEY = st.session_state.get("active_abuse_key", st.session_state.get("abuse_key_input", def_abuse))
URLSCAN_API_KEY = st.session_state.get("active_urlscan_key", st.session_state.get("urlscan_key_input", def_urlscan))
GREYNOISE_API_KEY = st.session_state.get("active_greynoise_key", st.session_state.get("greynoise_key_input", def_greynoise))
HIBP_API_KEY = st.session_state.get("active_hibp_key", st.session_state.get("hibp_key_input", def_hibp))

# -----------------------------------------------------------------------------
# 4. HEADER DA APLICAÇÃO & STATUS DA API
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Cyber Threat Research - Caçador de Ameaças V1.4</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Threat Hunting, Detection Engineering & Dynamic Threat Mapping</div>', unsafe_allow_html=True)

status_cols = st.columns(5)
status_cols[0].caption("🟢 VT" if VT_API_KEY else "🔴 VT")
status_cols[1].caption("🟢 AbuseIPDB" if ABUSE_API_KEY else "🔴 AbuseIPDB")
status_cols[2].caption("🟢 urlscan" if URLSCAN_API_KEY else "🔴 urlscan")
status_cols[3].caption("🟢 GreyNoise" if GREYNOISE_API_KEY else "🔴 GreyNoise")
status_cols[4].caption("🟢 HIBP" if HIBP_API_KEY else "🔴 HIBP")

# -----------------------------------------------------------------------------
# 5. QUICK-ACCESS THREAT INTEL HUB
# -----------------------------------------------------------------------------
with st.expander("🔗 **Quick-Access Threat Intel & Investigation Hub**", expanded=False):
    col_link1, col_link2, col_link3, col_link4, col_link5, col_link6 = st.columns(6)
    with col_link1:
        st.markdown('<a href="https://www.phishtool.com/" target="_blank" class="tool-card"><div class="tool-title">📧 PhishTool</div><div class="tool-desc">Triagem de e-mails maliciosos.</div></a>', unsafe_allow_html=True)
    with col_link2:
        st.markdown('<a href="https://bazaar.abuse.ch/" target="_blank" class="tool-card"><div class="tool-title">☣️ MalwareBazaar</div><div class="tool-desc">Amostras abertas de malware.</div></a>', unsafe_allow_html=True)
    with col_link3:
        st.markdown('<a href="https://www.hybrid-analysis.com/" target="_blank" class="tool-card"><div class="tool-title">🔬 Hybrid Analysis</div><div class="tool-desc">Sandbox dinâmica gratuita.</div></a>', unsafe_allow_html=True)
    with col_link4:
        st.markdown('<a href="https://www.shodan.io/" target="_blank" class="tool-card"><div class="tool-title">🌐 Shodan</div><div class="tool-desc">Exposição de serviços de rede.</div></a>', unsafe_allow_html=True)
    with col_link5:
        st.markdown('<a href="https://www.verexif.com/" target="_blank" class="tool-card"><div class="tool-title">📷 VerExif Online</div><div class="tool-desc">Metadados de imagem.</div></a>', unsafe_allow_html=True)
    with col_link6:
        st.markdown('<a href="https://mxtoolbox.com/" target="_blank" class="tool-card"><div class="tool-title">🛠️ MXToolbox</div><div class="tool-desc">Análise DNS, MX, SPF, DKIM.</div></a>', unsafe_allow_html=True)

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

# --- GreyNoise ---
def check_greynoise(ip_address):
    if not GREYNOISE_API_KEY:
        return {"error": "Sem API Key"}
    url = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            return {"message": "IP não catalogado como ruído generalizado."}
        return {"error": f"HTTP {res.status_code}"}
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

# --- Have I Been Pwned (HIBP) ---
def check_hibp_account(account):
    if not HIBP_API_KEY:
        return {"error": "Sem API Key"}
    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "ThreatHunter-App"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}?truncateResponse=false"
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            return []
        return {"error": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# -----------------------------------------------------------------------------
# 7. NAVEGAÇÃO POR ABAS OPERACIONAIS
# -----------------------------------------------------------------------------
tab_iocs, tab_hypotheses, tab_queries, tab_urlscan, tab_greynoise, tab_entropy, tab_email = st.tabs([
    "🔍 Extrator & VT",
    "🎯 Central de Hipóteses",
    "🎯 SIEM Queries",
    "🌐 urlscan.io",
    "📡 GreyNoise",
    "📊 Entropia",
    "📧 E-mail & HIBP"
])

# =============================================================================
# ABA 1: EXTRATOR, VIRUSTOTAL & ABUSEIPDB
# =============================================================================
with tab_iocs:
    st.header("🔍 Extrator de IOCs & Threat Intelligence")
    raw_text = st.text_area("Cole os IOCs para análise (IP, Domain, MD5, SHA256):", height=120)

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
    if "hypotheses_db" not in st.session_state:
        st.session_state["hypotheses_db"] = []
    
    hyp_list = st.session_state["hypotheses_db"]
    st.info(f"Total de hipóteses registradas: {len(hyp_list)}")

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
# ABA 5: GREYNOISE
# =============================================================================
with tab_greynoise:
    st.header("📡 GreyNoise - Filtro de Ruído da Internet")
    st.caption("Descubra se o IP examinado é um scanner inofensivo conhecido ou uma ameaça direcionada.")
    
    gn_ip = st.text_input("Insira o endereço IP para consulta no GreyNoise:", placeholder="8.8.8.8")
    if st.button("Consultar GreyNoise"):
        if gn_ip:
            gn_res = check_greynoise(gn_ip)
            if "error" in gn_res:
                st.error(gn_res["error"])
            else:
                st.json(gn_res)

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
# ABA 7: ANALISADOR DE E-MAIL & HIBP
# =============================================================================
with tab_email:
    st.header("📧 Analisador de E-mail & Have I Been Pwned")
    
    col_em1, col_em2 = st.columns(2)
    with col_em1:
        st.subheader("1. Análise de Cabeçalho")
        raw_header = st.text_area("Cole o cabeçalho bruto (Raw Header):", height=150)
        if st.button("Analisar Registros DNS/SPF"):
            spf = re.search(r'spf=(\w+)', raw_header, re.I)
            dkim = re.search(r'dkim=(\w+)', raw_header, re.I)
            st.write(f"SPF: {spf.group(1).upper() if spf else 'N/A'}")
            st.write(f"DKIM: {dkim.group(1).upper() if dkim else 'N/A'}")

    with col_em2:
        st.subheader("2. Checar Vazamentos (HIBP)")
        target_email = st.text_input("E-mail para consulta na HIBP:", placeholder="vitima@empresa.com")
        if st.button("Verificar Vazamentos"):
            if target_email:
                hibp_res = check_hibp_account(target_email)
                if isinstance(hibp_res, list):
                    if len(hibp_res) > 0:
                        st.error(f"🚨 Encontrado em {len(hibp_res)} vazamentos!")
                        st.json(hibp_res)
                    else:
                        st.success("✅ Nenhum vazamento registrado para esta conta.")
                else:
                    st.warning(f"Erro/Status: {hibp_res}")

# -----------------------------------------------------------------------------
# 8. RODAPÉ
# -----------------------------------------------------------------------------
st.markdown("""
    <div class="footer-text">
        CTRDEFENSE.BLOG &copy; 2026 | Cyber Threat Research - Caçador de Ameaças V1.4
    </div>
""", unsafe_allow_html=True)
