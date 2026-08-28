import re
import math
import time
import base64
import ipaddress
import urllib.parse
import concurrent.futures
from datetime import datetime

import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# 1. CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Cyber Threat Research - Caçador de Ameaças V3.6",
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

        .mini-field {
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid rgba(51, 65, 85, 0.5);
            border-radius: 8px;
            padding: 8px 12px;
            height: 100%;
        }
        .mini-field-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748b;
            margin-bottom: 2px;
        }
        .mini-field-value {
            font-size: 0.92rem;
            font-weight: 600;
            color: #38bdf8;
            line-height: 1.3;
            word-break: break-word;
        }
        .mini-field-extra {
            font-size: 0.75rem;
            color: #94a3b8;
            margin-top: 1px;
        }

        .no-key-badge {
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            background: rgba(34, 197, 94, 0.12);
            color: #4ade80;
            border: 1px solid rgba(74, 222, 128, 0.35);
            border-radius: 999px;
            padding: 1px 8px;
            margin-left: 6px;
        }

        .home-button {
            display: inline-block;
            padding: 10px 20px;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid rgba(0, 242, 254, 0.3);
            border-radius: 8px;
            color: #00f2fe;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            text-decoration: none;
            transition: all 0.3s;
            cursor: pointer;
            margin-bottom: 20px;
        }

        .home-button:hover {
            border-color: #00f2fe;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.3);
            transform: translateY(-2px);
        }
    </style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 3. INTERNACIONALIZAÇÃO (i18n)
# -----------------------------------------------------------------------------
translations = {
    "Português": {
        "app_title": "Cyber Threat Research - Caçador de Ameaças V3.6",
        "app_subtitle": "Threat Hunting, Detection Engineering & Dynamic Threat Mapping",
        "sidebar_credentials": "🔑 Credenciais API",
        "vt_key": "VirusTotal API Key:",
        "abuse_key": "AbuseIPDB API Key:",
        "urlscan_key": "urlscan.io API Key:",
        "greynoise_key": "GreyNoise API Key (Business/Enterprise):",
        "botscout_key": "BotScout API Key (opcional):",
        "save": "💾 Salvar",
        "clear": "🗑️ Limpar",
        "home": "🏠 Home",
        "quick_hub": "🔗 Quick-Access Threat Intel & Investigation Hub",
        "tab_extrator": "🔍 Extrator de IOCs",
        "tab_abuseipdb": "🛡️ AbuseIPDB",
        "tab_hypotheses": "🎯 Central de Hipóteses",
        "tab_urlscan": "🌐 urlscan.io",
        "tab_greynoise": "📡 GreyNoise",
        "tab_vazamento": "🔓 Vazamento-Email",
        "tab_osint": "🧭 APT-Hunter & OSINT",
        "tab_cross": "🔗 Cross-Intel",
        "tab_manual": "🧰 Threat Intel Manual",
        "footer": "CTRDEFENSE.BLOG © 2026 | Cyber Threat Research - Caçador de Ameaças V3.6"
    },
    "English": {
        "app_title": "Cyber Threat Research - Threat Hunter V3.6",
        "app_subtitle": "Threat Hunting, Detection Engineering & Dynamic Threat Mapping",
        "sidebar_credentials": "🔑 API Credentials",
        "vt_key": "VirusTotal API Key:",
        "abuse_key": "AbuseIPDB API Key:",
        "urlscan_key": "urlscan.io API Key:",
        "greynoise_key": "GreyNoise API Key (Business/Enterprise):",
        "botscout_key": "BotScout API Key (optional):",
        "save": "💾 Save",
        "clear": "🗑️ Clear",
        "home": "🏠 Home",
        "quick_hub": "🔗 Quick-Access Threat Intel & Investigation Hub",
        "tab_extrator": "🔍 IOC Extractor",
        "tab_abuseipdb": "🛡️ AbuseIPDB",
        "tab_hypotheses": "🎯 Hypothesis Center",
        "tab_urlscan": "🌐 urlscan.io",
        "tab_greynoise": "📡 GreyNoise",
        "tab_vazamento": "🔓 Email Leak",
        "tab_osint": "🧭 APT-Hunter & OSINT",
        "tab_cross": "🔗 Cross-Intel",
        "tab_manual": "🧰 Threat Intel Manual",
        "footer": "CTRDEFENSE.BLOG © 2026 | Cyber Threat Research - Threat Hunter V3.6"
    },
    "Español": {
        "app_title": "Cyber Threat Research - Cazador de Amenazas V3.6",
        "app_subtitle": "Threat Hunting, Detection Engineering & Dynamic Threat Mapping",
        "sidebar_credentials": "🔑 Credenciales API",
        "vt_key": "Clave API VirusTotal:",
        "abuse_key": "Clave API AbuseIPDB:",
        "urlscan_key": "Clave API urlscan.io:",
        "greynoise_key": "Clave API GreyNoise (Business/Enterprise):",
        "botscout_key": "Clave API BotScout (opcional):",
        "save": "💾 Guardar",
        "clear": "🗑️ Limpiar",
        "home": "🏠 Inicio",
        "quick_hub": "🔗 Acceso rápido a Inteligencia de Amenazas",
        "tab_extrator": "🔍 Extractor de IOCs",
        "tab_abuseipdb": "🛡️ AbuseIPDB",
        "tab_hypotheses": "🎯 Centro de Hipótesis",
        "tab_urlscan": "🌐 urlscan.io",
        "tab_greynoise": "📡 GreyNoise",
        "tab_vazamento": "🔓 Fuga de Email",
        "tab_osint": "🧭 APT-Hunter & OSINT",
        "tab_cross": "🔗 Cross-Intel",
        "tab_manual": "🧰 Manual de Inteligencia",
        "footer": "CTRDEFENSE.BLOG © 2026 | Cyber Threat Research - Cazador de Amenazas V3.6"
    },
    "Français": {
        "app_title": "Cyber Threat Research - Chasseur de Menaces V3.6",
        "app_subtitle": "Threat Hunting, Detection Engineering & Dynamic Threat Mapping",
        "sidebar_credentials": "🔑 Identifiants API",
        "vt_key": "Clé API VirusTotal :",
        "abuse_key": "Clé API AbuseIPDB :",
        "urlscan_key": "Clé API urlscan.io :",
        "greynoise_key": "Clé API GreyNoise (Business/Enterprise) :",
        "botscout_key": "Clé API BotScout (optionnel) :",
        "save": "💾 Enregistrer",
        "clear": "🗑️ Effacer",
        "home": "🏠 Accueil",
        "quick_hub": "🔗 Accès rapide aux renseignements sur les menaces",
        "tab_extrator": "🔍 Extracteur d'IOC",
        "tab_abuseipdb": "🛡️ AbuseIPDB",
        "tab_hypotheses": "🎯 Centre d'hypothèses",
        "tab_urlscan": "🌐 urlscan.io",
        "tab_greynoise": "📡 GreyNoise",
        "tab_vazamento": "🔓 Fuite d'email",
        "tab_osint": "🧭 APT-Hunter & OSINT",
        "tab_cross": "🔗 Cross-Intel",
        "tab_manual": "🧰 Manuel de Threat Intel",
        "footer": "CTRDEFENSE.BLOG © 2026 | Cyber Threat Research - Chasseur de Menaces V3.6"
    },
    "Deutsch": {
        "app_title": "Cyber Threat Research - Bedrohungsjäger V3.6",
        "app_subtitle": "Threat Hunting, Detection Engineering & Dynamic Threat Mapping",
        "sidebar_credentials": "🔑 API-Zugangsdaten",
        "vt_key": "VirusTotal API-Schlüssel:",
        "abuse_key": "AbuseIPDB API-Schlüssel:",
        "urlscan_key": "urlscan.io API-Schlüssel:",
        "greynoise_key": "GreyNoise API-Schlüssel (Business/Enterprise):",
        "botscout_key": "BotScout API-Schlüssel (optional):",
        "save": "💾 Speichern",
        "clear": "🗑️ Löschen",
        "home": "🏠 Startseite",
        "quick_hub": "🔗 Schnellzugriff auf Threat Intel",
        "tab_extrator": "🔍 IOC-Extraktor",
        "tab_abuseipdb": "🛡️ AbuseIPDB",
        "tab_hypotheses": "🎯 Hypothesen-Zentrum",
        "tab_urlscan": "🌐 urlscan.io",
        "tab_greynoise": "📡 GreyNoise",
        "tab_vazamento": "🔓 E-Mail-Leck",
        "tab_osint": "🧭 APT-Hunter & OSINT",
        "tab_cross": "🔗 Cross-Intel",
        "tab_manual": "🧰 Threat-Intel-Handbuch",
        "footer": "CTRDEFENSE.BLOG © 2026 | Cyber Threat Research - Bedrohungsjäger V3.6"
    }
}

# Seletor de idioma na sidebar (antes das credenciais)
with st.sidebar:
    st.markdown("### 🌐 Idioma / Language")
    selected_lang = st.selectbox(
        "Idioma / Language",
        options=list(translations.keys()),
        index=0,
        key="language_selector"
    )
    lang = translations[selected_lang]

# -----------------------------------------------------------------------------
# 3. GERENCIAMENTO SEGURO DAS API KEYS NA SIDEBAR
# -----------------------------------------------------------------------------
def get_secret(name):
    try:
        return st.secrets.get(name, "")
    except Exception:
        return ""

with st.sidebar:
    st.markdown(f"### {lang['sidebar_credentials']}")

    def_vt = get_secret("VIRUSTOTAL_API_KEY")
    def_abuse = get_secret("ABUSEIPDB_API_KEY")
    def_urlscan = get_secret("URLSCAN_API_KEY")
    def_greynoise = get_secret("GREYNOISE_API_KEY")
    def_botscout = get_secret("BOTSCOUT_API_KEY")

    user_vt_key = st.text_input(lang["vt_key"], value=st.session_state.get("vt_key_input", def_vt), type="password", key="vt_key_input")
    user_abuse_key = st.text_input(lang["abuse_key"], value=st.session_state.get("abuse_key_input", def_abuse), type="password", key="abuse_key_input")
    user_urlscan_key = st.text_input(lang["urlscan_key"], value=st.session_state.get("urlscan_key_input", def_urlscan), type="password", key="urlscan_key_input")
    user_greynoise_key = st.text_input(lang["greynoise_key"], value=st.session_state.get("greynoise_key_input", def_greynoise), type="password", key="greynoise_key_input")
    user_botscout_key = st.text_input(lang["botscout_key"], value=st.session_state.get("botscout_key_input", def_botscout), type="password", key="botscout_key_input")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button(lang["save"], use_container_width=True):
            st.session_state["active_vt_key"] = user_vt_key
            st.session_state["active_abuse_key"] = user_abuse_key
            st.session_state["active_urlscan_key"] = user_urlscan_key
            st.session_state["active_greynoise_key"] = user_greynoise_key
            st.session_state["active_botscout_key"] = user_botscout_key
            st.success("✅")
            st.rerun()

    with col_btn2:
        if st.button(lang["clear"], use_container_width=True):
            keys_to_clear = ["vt_key_input", "abuse_key_input", "urlscan_key_input",
                            "greynoise_key_input", "botscout_key_input",
                            "active_vt_key", "active_abuse_key", "active_urlscan_key", "active_greynoise_key",
                            "active_botscout_key"]
            for k in keys_to_clear:
                if k in st.session_state:
                    del st.session_state[k]
            st.warning("✅")
            st.rerun()

    st.divider()

VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", def_vt))
ABUSE_API_KEY = st.session_state.get("active_abuse_key", st.session_state.get("abuse_key_input", def_abuse))
URLSCAN_API_KEY = st.session_state.get("active_urlscan_key", st.session_state.get("urlscan_key_input", def_urlscan))
GREYNOISE_API_KEY = st.session_state.get("active_greynoise_key", st.session_state.get("greynoise_key_input", def_greynoise))
BOTSCOUT_API_KEY = st.session_state.get("active_botscout_key", st.session_state.get("botscout_key_input", def_botscout))

# -----------------------------------------------------------------------------
# 4. HEADER DA APLICAÇÃO & STATUS DA API
# -----------------------------------------------------------------------------
st.markdown(f'<div class="main-header">🛡️ {lang["app_title"]}</div>', unsafe_allow_html=True)
st.markdown(f'<div class="sub-header">{lang["app_subtitle"]}</div>', unsafe_allow_html=True)

# Botão Home
if st.button(lang["home"], key="home_button"):
    st.session_state.clear()
    st.rerun()

status_cols = st.columns(7)
status_cols[0].caption("🟢 VT" if VT_API_KEY else "🟡 VT")
status_cols[1].caption("🟢 AbuseIPDB" if ABUSE_API_KEY else "🟡 AbuseIPDB")
status_cols[2].caption("🟢 urlscan" if URLSCAN_API_KEY else "🟢 urlscan")
status_cols[3].caption("🟢 GreyNoise" if GREYNOISE_API_KEY else "🟢 GreyNoise")
status_cols[4].caption("🟢 XposedOrNot")
status_cols[5].caption("🟢 Shodan InternetDB")
status_cols[6].caption("🟢 ip-api.com")

if not VT_API_KEY or not ABUSE_API_KEY:
    st.caption("🟡 VirusTotal e AbuseIPDB exigem chave. Fallback OSINT ativo para IPs.")

# -----------------------------------------------------------------------------
# 5. QUICK-ACCESS THREAT INTEL HUB
# -----------------------------------------------------------------------------
with st.expander(lang["quick_hub"], expanded=False):
    st.markdown("""
        <div class="tool-grid">
            <a href="https://www.phishtool.com/" target="_blank" class="tool-card">
                <div class="tool-title">📧 PhishTool</div>
                <div class="tool-desc">Email triage</div>
            </a>
            <a href="https://bazaar.abuse.ch/" target="_blank" class="tool-card">
                <div class="tool-title">☣️ MalwareBazaar</div>
                <div class="tool-desc">Malware samples</div>
            </a>
            <a href="https://www.hybrid-analysis.com/" target="_blank" class="tool-card">
                <div class="tool-title">🔬 Hybrid Analysis</div>
                <div class="tool-desc">Free sandbox</div>
            </a>
            <a href="https://www.shodan.io/" target="_blank" class="tool-card">
                <div class="tool-title">🌐 Shodan</div>
                <div class="tool-desc">Network exposure</div>
            </a>
            <a href="https://www.verexif.com/" target="_blank" class="tool-card">
                <div class="tool-title">📷 VerExif</div>
                <div class="tool-desc">Image metadata</div>
            </a>
            <a href="https://mxtoolbox.com/" target="_blank" class="tool-card">
                <div class="tool-title">🛠️ MXToolbox</div>
                <div class="tool-desc">DNS, MX, SPF, DKIM</div>
            </a>
        </div>
    """, unsafe_allow_html=True)

st.divider()

# -----------------------------------------------------------------------------
# 6. MÓDULOS DE INTEGRAÇÃO COM APIS EXTERNAS
# -----------------------------------------------------------------------------

def is_valid_ipv4(ip_address):
    """Valida IPv4 para evitar consultas inválidas às APIs."""
    try:
        return ipaddress.ip_address(ip_address).version == 4
    except ValueError:
        return False


def render_country_field(container, label, value, extra=""):
    """Exibe um campo curto (País, Cidade, IP, AS...) com fonte reduzida."""
    extra_html = f'<div class="mini-field-extra">{extra}</div>' if extra else ""
    container.markdown(
        f"""<div class="mini-field">
                <div class="mini-field-label">{label}</div>
                <div class="mini-field-value">{value}</div>
                {extra_html}
            </div>""",
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# 6.1 FONTES OSINT 100% SEM CHAVE DE API (FALLBACK AUTOMÁTICO)
# -----------------------------------------------------------------------------

def check_shodan_internetdb(ip_address):
    """Consulta a Shodan InternetDB (https://internetdb.shodan.io) — gratuita,
    sem necessidade de conta ou API key."""
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}
    try:
        res = requests.get(f"https://internetdb.shodan.io/{ip_address}", timeout=8)
        if res.status_code == 200:
            data = res.json()
            data["_source"] = "Shodan InternetDB (sem chave)"
            return data
        if res.status_code == 404:
            return {"message": "Nenhuma informação de varredura disponível para este IP na InternetDB."}
        return {"error": f"HTTP {res.status_code}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com a Shodan InternetDB: {exc}"}


def check_ip_api_geo(ip_address):
    """Consulta o ip-api.com (endpoint gratuito, sem chave, ~45 req/min)."""
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}
    try:
        res = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query"},
            timeout=8,
        )
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "fail":
                return {"error": data.get("message", "Consulta falhou no ip-api.com")}
            data["_source"] = "ip-api.com (sem chave)"
            return data
        if res.status_code == 429:
            return {"error": "Limite de requisições do ip-api.com atingido (45/min). Aguarde um instante."}
        return {"error": f"HTTP {res.status_code}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com o ip-api.com: {exc}"}


def get_free_ip_context(ip_address):
    """Combina Shodan InternetDB + ip-api.com em um único contexto OSINT 'sem chave'."""
    shodan_data = check_shodan_internetdb(ip_address)
    geo_data = check_ip_api_geo(ip_address)

    ports = shodan_data.get("ports", []) if "error" not in shodan_data and "message" not in shodan_data else []
    vulns = shodan_data.get("vulns", []) if "error" not in shodan_data and "message" not in shodan_data else []
    tags = shodan_data.get("tags", []) if "error" not in shodan_data and "message" not in shodan_data else []
    hostnames = shodan_data.get("hostnames", []) if "error" not in shodan_data and "message" not in shodan_data else []

    country = geo_data.get("country") if "error" not in geo_data else None
    country_code = geo_data.get("countryCode") if "error" not in geo_data else ""
    isp_org = " / ".join(filter(None, [geo_data.get("isp"), geo_data.get("org")])) if "error" not in geo_data else "N/D"

    return {
        "shodan_raw": shodan_data,
        "geo_raw": geo_data,
        "ports": ports,
        "vulns": vulns,
        "tags": tags,
        "hostnames": hostnames,
        "country": country or "N/D",
        "country_code": country_code,
        "region": geo_data.get("regionName", "") if "error" not in geo_data else "",
        "city": geo_data.get("city", "N/D") if "error" not in geo_data else "N/D",
        "isp_org": isp_org,
        "asn": geo_data.get("as", "N/D") if "error" not in geo_data else "N/D",
        "is_proxy": geo_data.get("proxy"),
        "is_hosting": geo_data.get("hosting"),
        "shodan_error": shodan_data.get("error"),
        "geo_error": geo_data.get("error"),
    }


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

_VT_IP_DEFAULTS = {
    "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0,
    "country": "N/D", "as_owner": "N/D", "asn": "N/D", "network": "N/D", "rir": "N/D",
    "votes_malicious": 0, "votes_harmless": 0, "last_analysis_human": "N/D",
    "malicious_engines": [],
}


def parse_vt_details(vt_response):
    if "error" in vt_response:
        base = {"verdict": f"⚠️ {vt_response['error']}", "score": "N/A", "tags": "N/A", "file_name": "N/D", "file_type": "N/D", "file_size": "N/D"}
        base.update(_VT_IP_DEFAULTS)
        return base
    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())
        tags = attrs.get("tags", [])[:3]
        meaningful_name = attrs.get("meaningful_name", "")
        names_list = attrs.get("names", [])
        primary_name = meaningful_name if meaningful_name else (names_list[0] if names_list else "Desconhecido")
        file_type = attrs.get("type_description", attrs.get("magic", "N/D"))
        file_size = attrs.get("size", "N/D")

        if malicious > 0:
            verdict = f"🚨 Malicioso ({malicious}/{total})"
        elif suspicious > 0:
            verdict = f"🟡 Suspeito ({suspicious}/{total})"
        else:
            verdict = f"✅ Limpo ({harmless}/{total})"

        malicious_engines = [
            engine for engine, res in (attrs.get("last_analysis_results", {}) or {}).items()
            if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious")
        ][:10]

        votes = attrs.get("total_votes", {}) or {}
        last_analysis_ts = attrs.get("last_analysis_date")
        last_analysis_human = "N/D"
        if isinstance(last_analysis_ts, (int, float)):
            try:
                last_analysis_human = datetime.utcfromtimestamp(last_analysis_ts).strftime("%d/%m/%Y %H:%M UTC")
            except (OSError, OverflowError, ValueError):
                last_analysis_human = "N/D"

        return {
            "verdict": verdict,
            "score": attrs.get("reputation", 0),
            "tags": ", ".join(tags) if tags else "Sem Tags",
            "file_name": primary_name,
            "file_type": file_type,
            "file_size": f"{file_size:,} bytes" if isinstance(file_size, int) else file_size,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "country": attrs.get("country") or "N/D",
            "as_owner": attrs.get("as_owner") or "N/D",
            "asn": attrs.get("asn", "N/D"),
            "network": attrs.get("network") or "N/D",
            "rir": attrs.get("regional_internet_registry") or "N/D",
            "votes_malicious": votes.get("malicious", 0),
            "votes_harmless": votes.get("harmless", 0),
            "last_analysis_human": last_analysis_human,
            "malicious_engines": malicious_engines,
        }
    except KeyError:
        base = {"verdict": "Erro na estrutura", "score": "N/A", "tags": "N/D", "file_name": "N/D", "file_type": "N/D", "file_size": "N/D"}
        base.update(_VT_IP_DEFAULTS)
        return base

# --- AbuseIPDB ---
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def check_abuseipdb(ip_address):
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}
    if not ABUSE_API_KEY:
        return {"error": "Sem API Key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": "true"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        if response.status_code == 200:
            data = response.json()["data"]

            category_counts = {}
            for rep in data.get("reports", []) or []:
                for cat_id in rep.get("categories", []) or []:
                    name = ABUSEIPDB_CATEGORIES.get(cat_id, f"Categoria {cat_id}")
                    category_counts[name] = category_counts.get(name, 0) + 1
            top_categories = sorted(category_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

            return {
                "score": f"{data.get('abuseConfidenceScore', 0)}%",
                "score_raw": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "distinct_reporters": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode") or "N/D",
                "country_name": data.get("countryName") or "N/D",
                "isp": data.get("isp") or "N/D",
                "domain": data.get("domain") or "N/D",
                "hostnames": data.get("hostnames") or [],
                "usage_type": data.get("usageType") or "N/D",
                "is_whitelisted": data.get("isWhitelisted"),
                "is_public": data.get("isPublic"),
                "is_tor": data.get("isTor"),
                "last_reported_at": data.get("lastReportedAt") or "Nunca reportado",
                "top_categories": top_categories,
            }
        if response.status_code == 429:
            return {"error": "Limite de requisições do AbuseIPDB atingido."}
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# --- GreyNoise (Community e API autenticada v3) ---
def check_greynoise(ip_address):
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}

    if GREYNOISE_API_KEY:
        url = f"https://api.greynoise.io/v3/ip/{ip_address}"
        headers = {"Accept": "application/json", "key": GREYNOISE_API_KEY}
    else:
        url = f"https://api.greynoise.io/v3/community/{ip_address}"
        headers = {"Accept": "application/json"}

    try:
        res = requests.get(url, headers=headers, timeout=10)

        if res.status_code == 200:
            return res.json()
        if res.status_code == 400:
            return {"error": "IP inválido ou não roteável para a consulta GreyNoise."}
        if res.status_code == 401:
            return {"error": "Chave API do GreyNoise inválida ou sem permissão."}
        if res.status_code == 403:
            return {"error": "A chave GreyNoise não possui acesso ao endpoint solicitado."}
        if res.status_code == 404:
            return {"message": "IP não catalogado no GreyNoise."}
        if res.status_code == 429:
            return {"error": "Limite de requisições atingido no GreyNoise."}

        return {"error": f"HTTP {res.status_code}: {res.text[:300]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com GreyNoise: {exc}"}


def _gn_tag_names(tags):
    names = []
    for t in tags or []:
        if isinstance(t, dict):
            names.append(t.get("name") or t.get("slug") or "Tag")
        else:
            names.append(str(t))
    return names


def extract_greynoise_report(gn_res):
    if "internet_scanner_intelligence" in gn_res or "business_service_intelligence" in gn_res:
        isi = gn_res.get("internet_scanner_intelligence", {}) or {}
        bsi = gn_res.get("business_service_intelligence", {}) or {}
        meta = isi.get("metadata", {}) or {}
        raw = isi.get("raw_data", {}) or {}

        found_scanner = bool(isi.get("found"))
        found_business = bool(bsi.get("found"))
        classification = (isi.get("classification") or "").strip()
        if not classification:
            classification = "benign" if found_business else ("unknown" if not found_scanner else "unknown")

        return {
            "mode": "full",
            "ip": gn_res.get("ip", "N/D"),
            "found_scanner": found_scanner,
            "found_business": found_business,
            "classification": classification,
            "actor": isi.get("actor") or "Desconhecido",
            "first_seen": isi.get("first_seen") or "N/D",
            "last_seen": isi.get("last_seen") or "N/D",
            "spoofable": isi.get("spoofable"),
            "vpn": isi.get("vpn"),
            "vpn_service": isi.get("vpn_service") or "",
            "tor": isi.get("tor"),
            "bot": isi.get("bot"),
            "cves": isi.get("cves") or [],
            "tags": _gn_tag_names(isi.get("tags")),
            "tags_detail": isi.get("tags") or [],
            "organization": meta.get("organization") or "Desconhecido",
            "category": meta.get("category") or "N/D",
            "country": meta.get("source_country") or "N/D",
            "country_code": meta.get("source_country_code") or "",
            "city": meta.get("source_city") or "N/D",
            "region": meta.get("region") or "N/D",
            "asn": meta.get("asn") or "N/D",
            "domain": meta.get("domain") or "N/D",
            "rdns": meta.get("rdns") or "—",
            "os": meta.get("os") or "N/D",
            "sensor_count": meta.get("sensor_count", "N/D"),
            "sensor_hits": meta.get("sensor_hits", "N/D"),
            "mobile": meta.get("mobile"),
            "single_destination": meta.get("single_destination"),
            "destination_countries": meta.get("destination_countries") or [],
            "destination_asns": meta.get("destination_asns") or [],
            "scanned_ports": raw.get("scan") or [],
            "useragents": _dig(raw, "http", "useragent", default=[]) or [],
            "business_category": bsi.get("category") or "N/D",
            "business_name": bsi.get("name") or "N/D",
            "business_description": bsi.get("description") or "",
            "business_explanation": bsi.get("explanation") or "",
            "business_trust_level": bsi.get("trust_level") or "N/D",
            "link": f"https://viz.greynoise.io/ip/{gn_res.get('ip', '')}",
        }

    return {
        "mode": "community",
        "ip": gn_res.get("ip", "N/D"),
        "found_scanner": bool(gn_res.get("noise")),
        "found_business": bool(gn_res.get("riot")),
        "classification": gn_res.get("classification") or "unknown",
        "actor": gn_res.get("name") or "Desconhecido",
        "last_seen": gn_res.get("last_seen") or "N/D",
        "link": gn_res.get("link") or f"https://viz.greynoise.io/ip/{gn_res.get('ip', '')}",
    }


def render_greynoise_report(gn_res, queried_ip):
    report = extract_greynoise_report(gn_res)
    classification = (report.get("classification") or "unknown").lower()
    if classification == "malicious":
        label, level = "🔴 MALICIOSO", "error"
    elif classification == "suspicious":
        label, level = "🟡 SUSPEITO", "warning"
    elif classification == "benign":
        label, level = "🟢 BENIGNO", "success"
    else:
        label, level = "⚪ SEM CLASSIFICAÇÃO / NÃO OBSERVADO", "info"
    st.subheader("📊 Classificação e Resumo")
    getattr(st, level)(f"**{label}**  ·  IP `{report['ip']}`")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Noise (Scanner)", "Sim" if report.get("found_scanner") else "Não")
    col2.metric("Business Service (RIOT)", "Sim" if report.get("found_business") else "Não")
    if report["mode"] == "full":
        col3.metric("Trust Level", report.get("business_trust_level", "N/D"))
        col4.metric("Sensor Hits", report.get("sensor_hits", "N/D"))
    else:
        col3.metric("Ator Conhecido", report.get("actor", "N/D"))
        col4.metric("Last Seen", report.get("last_seen", "N/D"))
    if report["mode"] == "community":
        st.info(
            "ℹ️ Exibindo dados da **Community API** (gratuita). Campos como organização, ASN, "
            "tags detalhadas, comportamento de rede (VPN/Tor/Bot), CVEs e alvos de escaneamento "
            "exigem uma API Key Business/Enterprise na barra lateral."
        )
        st.markdown(f"**👤 Nome/Ator:** `{report.get('actor', 'N/D')}`")
        st.markdown(f"**⏳ Last Seen:** `{report.get('last_seen', 'N/D')}`")
        st.markdown(f"🔗 [Visualizar no GreyNoise Viz]({report['link']})")
        with st.expander("🔍 Ver JSON bruto"):
            st.json(gn_res)
        return
    st.markdown("### 📋 Perfil do Indicador")
    p1, p2 = st.columns(2)
    with p1:
        st.markdown(f"**👤 Actor:** `{report['actor']}`")
        st.markdown(f"**🏢 Organization:** `{report['organization']}`")
        st.markdown(f"**🗂️ Category:** `{report['category']}`")
        st.markdown(f"**🌐 ASN:** `{report['asn']}`  ·  **Domínio:** `{report['domain']}`")
        st.markdown(f"**📛 rDNS:** `{report['rdns']}`  ·  **SO detectado:** `{report['os']}`")
    with p2:
        flag = _country_flag(report.get("country_code", ""))
        render_country_field(st, "🌍 País de Origem", f"{flag} {report['country']}", report.get("region", ""))
        st.markdown(f"**🏙️ Cidade:** `{report['city']}`")
        st.markdown(f"**📅 First Seen:** `{report['first_seen']}`  ·  **Last Seen:** `{report['last_seen']}`")
        st.markdown(f"**📡 Sensor Count:** `{report['sensor_count']}`  ·  **Sensor Hits:** `{report['sensor_hits']}`")
    st.divider()
    st.markdown("### 🕵️ Comportamento de Rede")
    b1, b2, b3, b4, b5 = st.columns(5)
    b1.metric("Spoofable", "Sim" if report.get("spoofable") else "Não")
    b2.metric("VPN", "Sim" if report.get("vpn") else "Não")
    b3.metric("Tor", "Sim" if report.get("tor") else "Não")
    b4.metric("Bot", "Sim" if report.get("bot") else "Não")
    b5.metric("Dispositivo Móvel", "Sim" if report.get("mobile") else "Não")
    if report.get("vpn") and report.get("vpn_service"):
        st.caption(f"🔒 Serviço de VPN identificado: **{report['vpn_service']}**")
    st.divider()
    st.markdown("### 🏷️ Tags de Comportamento")
    tags_detail = report.get("tags_detail") or []
    if tags_detail:
        tag_rows = []
        for t in tags_detail:
            if isinstance(t, dict):
                tag_rows.append({
                    "Tag": t.get("name", "N/D"),
                    "Categoria": t.get("category", "N/D"),
                    "Intenção": t.get("intention", "N/D"),
                    "Bloqueio Recomendado?": "🚨 Sim" if t.get("recommend_block") else "Não",
                    "Descrição": t.get("description", ""),
                })
        if tag_rows:
            st.dataframe(pd.DataFrame(tag_rows), use_container_width=True, hide_index=True)
    elif report.get("tags"):
        tags_html = "".join(
            f"<span style='background-color:#1e293b; border: 1px solid #38bdf8; padding: 4px 8px; "
            f"border-radius: 4px; margin-right: 6px; font-family: monospace; font-size: 0.85em;'>{t}</span>"
            for t in report["tags"]
        )
        st.markdown(tags_html, unsafe_allow_html=True)
    else:
        st.caption("Nenhuma tag de comportamento associada a este IP.")
    if report.get("cves"):
        st.markdown(f"**⚠️ CVEs Ativamente Exploradas por este IP:** `{', '.join(report['cves'])}`")
    st.divider()
    st.markdown("### 🎯 Alvos Observados do Escaneamento")
    t1, t2, t3 = st.columns(3)
    t1.metric("Destino Único?", "Sim" if report.get("single_destination") else "Não")
    t2.metric("Países-Alvo", ", ".join(report.get("destination_countries") or []) or "N/D")
    t3.metric("ASNs-Alvo", ", ".join(report.get("destination_asns") or []) or "N/D")
    if report.get("scanned_ports"):
        st.caption("🔌 Portas/protocolos observados na varredura: " + ", ".join(str(p) for p in report["scanned_ports"][:20]))
    if report.get("useragents"):
        with st.expander("🧾 User-Agents observados nas requisições deste IP"):
            for ua in report["useragents"][:15]:
                st.code(str(ua), language="text")
    if report.get("found_business"):
        st.divider()
        st.markdown("### 🏢 Serviço Empresarial Conhecido (Business Service Intelligence)")
        st.success(
            f"**{report.get('business_name', 'N/D')}** · Categoria: {report.get('business_category', 'N/D')} "
            f"· Trust Level: {report.get('business_trust_level', 'N/D')}"
        )
        if report.get("business_description"):
            st.caption(report["business_description"])
        if report.get("business_explanation"):
            st.caption(f"ℹ️ {report['business_explanation']}")
    st.divider()
    st.markdown(f"🔗 [Visualizar relatório completo no GreyNoise Viz]({report['link']})")
    with st.expander("🔍 Ver JSON bruto completo (debug)"):
        st.json(gn_res)


# --- urlscan.io ---
def submit_urlscan(target_url):
    target_url = target_url.strip()
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"error": "URL inválida. Use uma URL completa, por exemplo: https://exemplo.com"}
    headers = {"Content-Type": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    data = {"url": target_url, "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return {"error": "Resposta inválida (JSON malformado) recebida do urlscan.io."}
        if response.status_code == 400:
            return {"error": f"Requisição rejeitada pelo urlscan.io: {response.text[:300]}"}
        if response.status_code == 401:
            return {"error": "Chave API do urlscan.io inválida."}
        if response.status_code == 429:
            msg = "Limite de requisições do urlscan.io atingido. Aguarde antes de tentar novamente."
            if not URLSCAN_API_KEY:
                msg += " Cotas anônimas (sem chave) são bem menores — cadastre uma API Key gratuita para aumentar o limite."
            return {"error": msg}
        return {"error": f"HTTP {response.status_code}: {response.text[:500]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com urlscan.io: {exc}"}


def search_urlscan(query, size=10):
    headers = {"Accept": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    try:
        response = requests.get("https://urlscan.io/api/v1/search/", headers=headers, params={"q": query, "size": size}, timeout=15)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return {"error": "Resposta inválida (JSON malformado) recebida da busca do urlscan.io."}
        if response.status_code == 429:
            return {"error": "Limite de requisições de busca do urlscan.io atingido."}
        return {"error": f"HTTP {response.status_code}: {response.text[:300]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com a busca do urlscan.io: {exc}"}


def check_urlscan_by_ip(ip_address):
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}
    search_res = search_urlscan(f'page.ip:"{ip_address}"', size=10)
    if "error" in search_res:
        return search_res
    hits = search_res.get("results", []) or []
    total = _dig(search_res, "total", default=len(hits))
    scans = []
    malicious_count = 0
    for hit in hits:
        page = hit.get("page", {}) or {}
        task = hit.get("task", {}) or {}
        verdicts_overall = _dig(hit, "verdicts", "overall", default={}) or {}
        is_malicious = bool(verdicts_overall.get("malicious"))
        if is_malicious:
            malicious_count += 1
        scans.append({
            "domain": page.get("domain", "N/D"),
            "url": page.get("url") or task.get("url", "N/D"),
            "country": page.get("country", "N/D"),
            "time": task.get("time", "N/D"),
            "malicious": is_malicious,
            "result_url": hit.get("result") or (f"https://urlscan.io/result/{task.get('uuid', '')}/" if task.get("uuid") else ""),
            "screenshot": hit.get("screenshot"),
        })
    return {
        "total": total,
        "returned": len(scans),
        "malicious_count": malicious_count,
        "scans": scans,
        "search_link": f"https://urlscan.io/search/#page.ip%3A%22{ip_address}%22",
    }


def get_urlscan_result(scan_uuid):
    headers = {"Accept": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return {"error": "Resposta inválida (JSON malformado) recebida do urlscan.io."}
        if response.status_code == 404:
            return {"__pending__": True}
        if response.status_code == 401:
            return {"error": "Chave API do urlscan.io inválida para consulta de resultado."}
        if response.status_code == 429:
            return {"error": "Limite de requisições do urlscan.io atingido durante a consulta do resultado."}
        return {"error": f"HTTP {response.status_code}: {response.text[:300]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com urlscan.io: {exc}"}


def poll_urlscan_result(scan_uuid, status_placeholder=None, progress_bar=None, initial_wait=15, poll_interval=5, max_wait=90):
    def _update(elapsed, message):
        if status_placeholder is not None:
            status_placeholder.info(message)
        if progress_bar is not None:
            progress_bar.progress(min(elapsed / max_wait, 1.0))
    _update(0, f"⏳ Scan enviado. Aguardando {initial_wait}s para o processamento inicial...")
    time.sleep(initial_wait)
    elapsed = initial_wait
    while True:
        result = get_urlscan_result(scan_uuid)
        if not (isinstance(result, dict) and result.get("__pending__")):
            if progress_bar is not None:
                progress_bar.progress(1.0)
            return result
        if elapsed >= max_wait:
            return {"error": "timeout"}
        _update(elapsed, f"⏳ Ainda processando no urlscan.io... ({elapsed}s / {max_wait}s)")
        time.sleep(poll_interval)
        elapsed += poll_interval


def _dig(source, *keys, default=None):
    current = source
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
    return default if current is None else current


def _country_flag(country_code):
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return ""
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())


def _format_scan_datetime(iso_ts):
    if not iso_ts:
        return "N/D"
    try:
        return datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M:%S UTC")
    except ValueError:
        return str(iso_ts)


def _brand_names(brands):
    names = []
    for b in brands or []:
        if isinstance(b, str):
            names.append(b)
        elif isinstance(b, dict):
            names.append(b.get("name") or b.get("key") or "Desconhecido")
    return names


def extract_urlscan_verdict(result):
    overall = _dig(result, "verdicts", "overall", default={}) or {}
    urlscan_v = _dig(result, "verdicts", "urlscan", default={}) or {}
    malicious = bool(overall.get("malicious"))
    score = overall.get("score", 0) or 0
    has_verdicts = overall.get("hasVerdicts", 0) or 0
    categories = overall.get("categories") or urlscan_v.get("categories") or []
    tags = overall.get("tags") or urlscan_v.get("tags") or []
    brands = _brand_names(overall.get("brands")) or _brand_names(urlscan_v.get("brands"))
    if malicious:
        label, level = "🔴 MALICIOSO", "error"
    elif score and score > 0:
        label, level = "🟡 SUSPEITO", "warning"
    elif has_verdicts:
        label, level = "🟢 NENHUMA AMEAÇA DETECTADA", "success"
    else:
        label, level = "⚪ SEM CLASSIFICAÇÃO DISPONÍVEL", "info"
    return {"label": label, "level": level, "score": score, "categories": categories, "tags": tags, "brands": brands}


def extract_urlscan_summary(result):
    task = result.get("task", {}) or {}
    page = result.get("page", {}) or {}
    stats = result.get("stats", {}) or {}
    requests_list = _dig(result, "data", "requests", default=[]) or []
    return {
        "title": page.get("title") or "(sem título)",
        "submitted_url": task.get("url", "N/D"),
        "final_url": page.get("url", "N/D"),
        "redirected": str(page.get("redirected", "")).lower() == "true",
        "scan_time": _format_scan_datetime(task.get("time")),
        "total_requests": len(requests_list),
        "unique_countries": stats.get("uniqCountries", "N/D"),
        "total_links": stats.get("totalLinks", "N/D"),
        "malicious_resources": stats.get("malicious", 0),
        "report_url": task.get("reportURL") or f"https://urlscan.io/result/{task.get('uuid', '')}/",
        "screenshot_url": task.get("screenshotURL"),
    }


def extract_urlscan_location(result):
    page = result.get("page", {}) or {}
    country = page.get("country", "") or ""
    return {
        "country": country or "N/D",
        "flag": _country_flag(country),
        "city": page.get("city") or "—",
        "ip": page.get("ip", "N/D"),
        "asn": page.get("asn", "N/D"),
        "asnname": page.get("asnname", "N/D"),
        "server": page.get("server") or "N/D",
        "ptr": page.get("ptr") or "—",
    }


def extract_urlscan_history(result):
    history = []
    redirects = _dig(result, "data", "redirects", default=[])
    if isinstance(redirects, list) and redirects:
        for idx, hop in enumerate(redirects, start=1):
            if isinstance(hop, dict):
                url = hop.get("url") or hop.get("to") or hop.get("location") or "N/D"
                via = hop.get("type") or hop.get("via") or hop.get("redirectType")
                if not via:
                    via = "JavaScript" if hop.get("js") else "HTTP"
            else:
                url, via = str(hop), "N/D"
            history.append({"#": idx, "URL": url, "Tipo": via})
        return history
    nav_hops = []
    for item in _dig(result, "data", "requests", default=[]) or []:
        if not isinstance(item, dict):
            continue
        req = item.get("request", {}) or {}
        req_inner = req.get("request", {}) or {}
        resp_inner = _dig(item, "response", "response", default={}) or {}
        status = resp_inner.get("status")
        is_navigation = req.get("type") == "Document"
        is_redirect_status = isinstance(status, int) and 300 <= status < 400
        if is_navigation or is_redirect_status:
            nav_hops.append({
                "timestamp": req.get("timestamp", 0),
                "url": req_inner.get("url") or resp_inner.get("url") or "N/D",
                "status": status,
            })
    nav_hops.sort(key=lambda h: h["timestamp"])
    seen = set()
    for hop in nav_hops:
        if hop["url"] in seen:
            continue
        seen.add(hop["url"])
        tipo = f"HTTP {hop['status']}" if isinstance(hop["status"], int) else "Navegação"
        history.append({"#": len(history) + 1, "URL": hop["url"], "Tipo": tipo})
    if not history:
        task_url = result.get("task", {}).get("url", "N/D")
        page_url = result.get("page", {}).get("url", "N/D")
        history.append({"#": 1, "URL": task_url, "Tipo": "URL Submetida"})
        if page_url and page_url != task_url:
            history.append({"#": 2, "URL": page_url, "Tipo": "URL Final"})
    return history


def extract_urlscan_transactions(result):
    rows = []
    for idx, item in enumerate(_dig(result, "data", "requests", default=[]) or [], start=1):
        if not isinstance(item, dict):
            continue
        req = item.get("request", {}) or {}
        req_inner = req.get("request", {}) or {}
        resp = item.get("response", {}) or {}
        resp_inner = resp.get("response", {}) or {}
        status = resp_inner.get("status")
        size_bytes = resp.get("encodedDataLength", resp_inner.get("encodedDataLength"))
        rows.append({
            "#": idx,
            "Método": req_inner.get("method", "—"),
            "URL": req_inner.get("url") or resp_inner.get("url") or "N/D",
            "Status": status if status is not None else "Sem resposta",
            "Tipo": req.get("type", "—"),
            "MIME": resp_inner.get("mimeType", "—"),
            "Tamanho (bytes)": size_bytes if isinstance(size_bytes, int) else "N/D",
            "IP Remoto": resp_inner.get("remoteIPAddress", "—"),
            "País": _dig(resp, "geoip", "country", default="—"),
            "ASN": _dig(resp, "asn", "asn", default="—"),
            "Hash SHA256": resp.get("hash", "—"),
        })
    return rows


def render_urlscan_report(result, target_scan_url):
    summary = extract_urlscan_summary(result)
    verdict = extract_urlscan_verdict(result)
    location = extract_urlscan_location(result)
    history = extract_urlscan_history(result)
    transactions = extract_urlscan_transactions(result)
    st.subheader("🎯 Resumo (Summary)")
    getattr(st, verdict["level"])(f"**{verdict['label']}**  ·  Score de Maliciosidade: `{verdict['score']}`")
    extra_bits = []
    if verdict["categories"]:
        extra_bits.append("Categorias: " + ", ".join(str(c) for c in verdict["categories"]))
    if verdict["brands"]:
        extra_bits.append("Marcas Detectadas: " + ", ".join(verdict["brands"]))
    if verdict["tags"]:
        extra_bits.append("Tags: " + ", ".join(str(t) for t in verdict["tags"]))
    if extra_bits:
        st.caption(" • ".join(extra_bits))
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Requisições HTTP", summary["total_requests"])
    m2.metric("Recursos Maliciosos", summary["malicious_resources"])
    m3.metric("Países Únicos", summary["unique_countries"])
    m4.metric("Houve Redirecionamento?", "Sim" if summary["redirected"] else "Não")
    st.markdown(f"**📄 Título da Página:** {summary['title']}")
    st.markdown(f"**🔗 URL Submetida:** `{summary['submitted_url']}`")
    st.markdown(f"**🏁 URL Final:** `{summary['final_url']}`")
    st.markdown(f"**🕒 Data/Hora do Scan:** {summary['scan_time']}")
    st.markdown(f"**📑 Relatório Completo no urlscan.io:** [{summary['report_url']}]({summary['report_url']})")
    st.divider()
    st.markdown("### 📍 Localização (Located) & Rede")
    l1, l2, l3, l4 = st.columns(4)
    render_country_field(l1, "País", f"{location['flag']} {location['country']}")
    render_country_field(l2, "Cidade", location['city'])
    render_country_field(l3, "IP", f"`{location['ip']}`")
    render_country_field(l4, "AS (ASN)", f"`{location['asn']}` · {location['asnname']}")
    st.caption(f"🖥️ Servidor (HTTP Server header): {location['server']}  ·  📛 PTR: {location['ptr']}")
    st.divider()
    st.markdown("### 🧭 Histórico de URL da Página (Page URL History)")
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
    else:
        st.caption("Nenhum redirecionamento detectado — a URL carregou diretamente.")
    st.divider()
    st.markdown(f"### 📡 Transações HTTP (HTTP Transactions) — {len(transactions)} requisições capturadas")
    if transactions:
        df_tx = pd.DataFrame(transactions)
        filter_txt = st.text_input("Filtrar transações por domínio/URL:", key="urlscan_tx_filter", placeholder="ex: googletagmanager.com")
        if filter_txt:
            df_tx = df_tx[df_tx["URL"].str.contains(filter_txt, case=False, na=False, regex=False)]
        st.dataframe(df_tx, use_container_width=True, hide_index=True, height=380)
        st.download_button("⬇️ Exportar Transações (CSV)", df_tx.to_csv(index=False).encode("utf-8"), file_name=f"urlscan_transactions_{urllib.parse.urlparse(target_scan_url).netloc or 'scan'}.csv", mime="text/csv")
    else:
        st.caption("Nenhuma transação HTTP foi capturada para esta página.")
    if summary.get("screenshot_url"):
        with st.expander("🖼️ Screenshot da Página Capturada"):
            try:
                shot_headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
                shot = requests.get(summary["screenshot_url"], headers=shot_headers, timeout=15)
                if shot.status_code == 200:
                    st.image(shot.content, use_container_width=True)
                else:
                    st.caption(f"Não foi possível carregar o screenshot (HTTP {shot.status_code}).")
            except requests.RequestException:
                st.caption("Não foi possível carregar o screenshot no momento.")
    with st.expander("🔍 Ver JSON bruto completo (debug)"):
        st.json(result)


def check_botscout_ip(ip_address):
    if not is_valid_ipv4(ip_address):
        return {"error": "IPv4 inválido."}
    params = {"ip": ip_address, "format": "xml"}
    if BOTSCOUT_API_KEY:
        params["key"] = BOTSCOUT_API_KEY
    try:
        res = requests.get("https://botscout.com/test/", params=params, timeout=10)
        if res.status_code != 200:
            return {"error": f"HTTP {res.status_code}: {res.text[:200]}"}
        body = res.text.strip()
        if body.startswith("!"):
            return {"error": body[1:].strip()}
        m = re.search(r"<matched>([YN])</matched>", body, re.I)
        c = re.search(r"<count>(\d+)</count>", body, re.I)
        return {"matched": (m.group(1).upper() == "Y") if m else None, "count": int(c.group(1)) if c else None, "raw": body}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com BotScout: {exc}"}


def check_botscout_email(email):
    email = (email or "").strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return {"error": "E-mail inválido."}
    params = {"mail": email, "format": "xml"}
    if BOTSCOUT_API_KEY:
        params["key"] = BOTSCOUT_API_KEY
    try:
        res = requests.get("https://botscout.com/test/", params=params, timeout=10)
        if res.status_code != 200:
            return {"error": f"HTTP {res.status_code}: {res.text[:200]}"}
        body = res.text.strip()
        if body.startswith("!"):
            return {"error": body[1:].strip()}
        m = re.search(r"<matched>([YN])</matched>", body, re.I)
        c = re.search(r"<count>(\d+)</count>", body, re.I)
        return {"matched": (m.group(1).upper() == "Y") if m else None, "count": int(c.group(1)) if c else None, "raw": body}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com BotScout: {exc}"}


def detect_osint_query_type(value):
    value = (value or "").strip()
    if is_valid_ipv4(value):
        return "IP"
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "MD5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return "SHA1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "SHA256"
    if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        return "EMAIL"
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, re.I):
        return "CVE"
    parsed = urllib.parse.urlparse(value if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I) else "http://" + value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        if value.lower().startswith(("http://", "https://")):
            return "URL"
        return "DOMAIN"
    return "TERM"


def vt_url_id(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def query_vt_universal(value, kind):
    if not VT_API_KEY:
        return {"error": "VirusTotal sem API Key."}
    endpoint = None
    item_id = value
    if kind == "IP":
        endpoint = "ip_addresses"
    elif kind in {"MD5", "SHA1", "SHA256"}:
        endpoint = "files"
    elif kind == "DOMAIN":
        endpoint = "domains"
    elif kind == "URL":
        endpoint = "urls"
        item_id = vt_url_id(value)
    else:
        return {"error": f"VirusTotal não possui consulta direta para o tipo {kind}."}
    return get_vt_data(endpoint, item_id)


def query_urlscan_universal(value, kind):
    if kind == "IP":
        return check_urlscan_by_ip(value)
    if kind == "DOMAIN":
        return search_urlscan(f'page.domain:"{value}"', size=10)
    if kind == "URL":
        return search_urlscan(f'page.url:"{value}"', size=10)
    return {"error": f"urlscan não oferece busca apropriada para {kind}."}


def render_osint_unified_report(query_value, query_kind, results):
    st.markdown("### 📊 Relatório Unificado de Threat Intelligence / OSINT")
    st.caption(f"Indicador: `{query_value}` · Tipo detectado: **{query_kind}**")
    source_rows = []
    for source, result in results.items():
        if not isinstance(result, dict):
            status = "Erro"
            detail = str(result)[:160]
        elif result.get("error"):
            status = "Erro / indisponível"
            detail = result.get("error", "")[:160]
        elif result.get("message"):
            status = "Sem correspondência"
            detail = result.get("message", "")[:160]
        elif result.get("configured") is False:
            status = "Não configurado"
            detail = result.get("message", "")[:160]
        else:
            status = "Consulta concluída"
            detail = "Dados recebidos"
        source_rows.append({"Fonte": source, "Status": status, "Resumo": detail})
    st.dataframe(pd.DataFrame(source_rows), use_container_width=True, hide_index=True)
    vt = results.get("VirusTotal", {})
    if isinstance(vt, dict) and "data" in vt:
        vt_attrs = vt.get("data", {}).get("attributes", {}) or {}
        stats = vt_attrs.get("last_analysis_stats", {}) or {}
        st.markdown("#### 🦠 VirusTotal")
        a,b,c,d = st.columns(4)
        a.metric("Maliciosos", stats.get("malicious", 0))
        b.metric("Suspeitos", stats.get("suspicious", 0))
        c.metric("Benignos", stats.get("harmless", 0))
        d.metric("Não detectados", stats.get("undetected", 0))
        vt_context = []
        for k in ("country", "as_owner", "asn", "network", "reputation", "registrar"):
            if vt_attrs.get(k) not in (None, ""):
                vt_context.append({"Atributo": k, "Valor": vt_attrs.get(k)})
        if vt_context:
            st.dataframe(pd.DataFrame(vt_context), use_container_width=True, hide_index=True)
    abuse = results.get("AbuseIPDB", {})
    if isinstance(abuse, dict) and "error" not in abuse and "message" not in abuse:
        st.markdown("#### 🛡️ AbuseIPDB")
        x,y,z = st.columns(3)
        x.metric("Abuse Confidence", abuse.get("score", "N/D"))
        y.metric("Reports", abuse.get("reports", 0))
        z.metric("País", abuse.get("country_name") or abuse.get("country") or "N/D")
        if abuse.get("top_categories"):
            st.write(pd.DataFrame(abuse["top_categories"], columns=["Categoria", "Ocorrências"]))
    elif isinstance(abuse, dict) and abuse.get("error"):
        st.warning(f"AbuseIPDB: {abuse['error']}")
    gn = results.get("GreyNoise", {})
    if isinstance(gn, dict) and "error" not in gn and "message" not in gn:
        report = extract_greynoise_report(gn)
        st.markdown("#### 📡 GreyNoise")
        p,q,r,s = st.columns(4)
        p.metric("Classificação", str(report.get("classification", "unknown")).upper())
        q.metric("Noise", "Sim" if report.get("found_scanner") else "Não")
        r.metric("RIOT", "Sim" if report.get("found_business") else "Não")
        s.metric("Last Seen", report.get("last_seen", "N/D"))
        st.caption(f"Ator: {report.get('actor', 'N/D')} · Organização: {report.get('organization', 'N/D')} · ASN: {report.get('asn', 'N/D')}")
    urlscan = results.get("urlscan", {})
    if isinstance(urlscan, dict) and "error" not in urlscan:
        scans = urlscan.get("scans") if "scans" in urlscan else urlscan.get("results", [])
        if isinstance(scans, list):
            st.markdown(f"#### 🌐 urlscan.io — {len(scans)} resultado(s)")
            rows = []
            for scan in scans[:20]:
                if isinstance(scan, dict):
                    page = scan.get("page", {}) or {}
                    task = scan.get("task", {}) or {}
                    rows.append({
                        "Domínio": page.get("domain", "N/D"),
                        "URL": page.get("url") or task.get("url", "N/D"),
                        "País": page.get("country", "N/D"),
                        "Data": task.get("time", "N/D"),
                        "Resultado": scan.get("result", "") or scan.get("result_url", ""),
                    })
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        elif urlscan.get("results"):
            st.json(urlscan.get("results"))
    sh = results.get("Shodan InternetDB", {})
    if isinstance(sh, dict) and "error" not in sh and "message" not in sh:
        st.markdown("#### 🔎 Shodan InternetDB")
        cc = st.columns(4)
        cc[0].metric("Portas", len(sh.get("ports", []) or []))
        cc[1].metric("CVEs", len(sh.get("vulns", []) or []))
        cc[2].metric("Hostnames", len(sh.get("hostnames", []) or []))
        cc[3].metric("Tags", len(sh.get("tags", []) or []))
        if sh.get("ports") or sh.get("vulns"):
            st.write({"ports": sh.get("ports", []), "vulns": sh.get("vulns", []), "tags": sh.get("tags", [])})
    geo = results.get("ip-api.com", {})
    if isinstance(geo, dict) and "error" not in geo and geo.get("status") == "success":
        st.markdown("#### 🌍 ip-api.com")
        geo_rows = [{"País": geo.get("country"), "Região": geo.get("regionName"), "Cidade": geo.get("city"), "ISP": geo.get("isp"), "Organização": geo.get("org"), "ASN": geo.get("as"), "Proxy": geo.get("proxy"), "Hosting": geo.get("hosting")}]
        st.dataframe(pd.DataFrame(geo_rows), use_container_width=True, hide_index=True)
    bs = results.get("BotScout", {})
    if isinstance(bs, dict) and "error" not in bs:
        st.markdown("#### 🤖 BotScout")
        st.info(f"Match: {'SIM' if bs.get('matched') else 'NÃO' if bs.get('matched') is not None else 'N/D'} · Correspondências: {bs.get('count', 'N/D')}")
    xo = results.get("XposedOrNot", {})
    if isinstance(xo, dict) and "error" not in xo and query_kind == "EMAIL":
        st.markdown("#### 🔓 XposedOrNot")
        breaches = xo.get("ExposedBreaches") or xo.get("exposedBreaches") or []
        if isinstance(breaches, dict):
            breaches = breaches.get("breaches_details") or breaches.get("breaches") or []
        st.metric("Vazamentos encontrados", len(breaches) if isinstance(breaches, list) else 0)
    with st.expander("🔍 JSON consolidado (debug)"):
        st.json(results)


def check_xposedornot_analytics(email):
    email = email.strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return {"error": "Endereço de e-mail inválido."}
    try:
        res = requests.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email}, timeout=10)
        if res.status_code == 200:
            return res.json()
        if res.status_code == 404:
            return {"status": "clean", "Error": "Not found"}
        if res.status_code == 429:
            return {"error": "Limite de requisições do XposedOrNot atingido."}
        return {"error": f"HTTP {res.status_code}: {res.text[:300]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com XposedOrNot: {exc}"}


# -----------------------------------------------------------------------------
# 7. NAVEGAÇÃO POR ABAS OPERACIONAIS
# -----------------------------------------------------------------------------
(
    tab_extrator,
    tab_abuseipdb,
    tab_hypotheses,
    tab_urlscan,
    tab_greynoise,
    tab_vazamento,
    tab_osint,
    tab_cross,
    tab_manual,
) = st.tabs([
    lang["tab_extrator"],
    lang["tab_abuseipdb"],
    lang["tab_hypotheses"],
    lang["tab_urlscan"],
    lang["tab_greynoise"],
    lang["tab_vazamento"],
    lang["tab_osint"],
    lang["tab_cross"],
    lang["tab_manual"],
])

# =============================================================================
# ABA 1: EXTRATOR DE IOCs
# =============================================================================
with tab_extrator:
    st.header(lang["tab_extrator"])
    raw_text = st.text_area("Cole os IOCs para análise e banimentos (IP, Domain, MD5, SHA256):", height=120)

    def extract_iocs(text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        ips = sorted({ip for ip in re.findall(ip_pattern, text) if is_valid_ipv4(ip)})
        urls = sorted(set(re.findall(url_pattern, text)))
        md5s = sorted(set(re.findall(md5_pattern, text)))
        sha256s = sorted(set(re.findall(sha256_pattern, text)))
        return ips, urls, md5s, sha256s

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
            if not VT_API_KEY:
                st.info("🟡 Sem chave do VirusTotal cadastrada. Use os links VT/HA abaixo para consulta manual.")
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
            st.subheader("🌐 Endereços IP (VirusTotal + Fallback OSINT sem chave)")
            if not VT_API_KEY:
                st.caption("🟢 VT exige chave; enquanto ausente, País/ISP/Portas/CVEs são preenchidos via Shodan InternetDB + ip-api.com.")
            ip_data = []
            for ip in ips:
                vt_info = parse_vt_details(get_vt_data("ip_addresses", ip)) if VT_API_KEY else None
                free_ctx = get_free_ip_context(ip)
                veredito_vt = vt_info["verdict"] if vt_info else "🟡 Sem chave VT"
                pais_info = free_ctx["country"] if free_ctx else "N/D"
                isp_info = free_ctx["isp_org"] if free_ctx else "N/D"
                portas_abertas = ", ".join(str(p) for p in (free_ctx["ports"][:10] if free_ctx else [])) or "—"
                vulns_shodan = ", ".join((free_ctx["vulns"][:5] if free_ctx else [])) or "—"
                ip_data.append({
                    "IP": ip,
                    "Veredito VT": veredito_vt,
                    "País": pais_info,
                    "ISP / Org": isp_info,
                    "Portas Abertas (Shodan)": portas_abertas,
                    "CVEs (Shodan)": vulns_shodan,
                    "Link VT": f"https://www.virustotal.com/gui/ip-address/{ip}",
                })
            st.dataframe(pd.DataFrame(ip_data), column_config={"Link VT": st.column_config.LinkColumn("VT ↗")}, use_container_width=True, hide_index=True)

# =============================================================================
# ABA 2: ABUSEIPDB (CONSULTA INDIVIDUAL)
# =============================================================================
with tab_abuseipdb:
    st.header(lang["tab_abuseipdb"])
    st.caption("Verifique a reputação de um endereço IP específico na base do AbuseIPDB.")
    if not ABUSE_API_KEY:
        st.warning("🔑 É necessária uma API Key do AbuseIPDB para consultas. Cadastre na barra lateral.")
    abuse_ip = st.text_input("Endereço IP para verificar:", key="abuse_single_ip")
    if st.button("Consultar AbuseIPDB", type="primary"):
        if not abuse_ip:
            st.warning("Informe um IP.")
        elif not is_valid_ipv4(abuse_ip.strip()):
            st.error("IP inválido.")
        else:
            with st.spinner("Consultando..."):
                res = check_abuseipdb(abuse_ip.strip())
                if "error" in res:
                    st.error(res["error"])
                else:
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Score de Abuso", res.get("score", "N/D"))
                    col2.metric("Total de Reports", res.get("reports", 0))
                    col3.metric("Usuários Distintos", res.get("distinct_reporters", 0))
                    st.markdown(f"**País:** {res.get('country_name')} ({res.get('country')})")
                    st.markdown(f"**ISP:** {res.get('isp')}")
                    st.markdown(f"**Domínio:** {res.get('domain')}")
                    st.markdown(f"**Uso:** {res.get('usage_type')}")
                    st.markdown(f"**Whitelisted:** {'Sim' if res.get('is_whitelisted') else 'Não'}")
                    st.markdown(f"**Último Reporte:** {res.get('last_reported_at')}")
                    if res.get('top_categories'):
                        st.markdown("**Categorias mais reportadas:**")
                        st.write(pd.DataFrame(res["top_categories"], columns=["Categoria", "Ocorrências"]))

# =============================================================================
# ABA 3: CENTRAL DE HIPÓTESES
# =============================================================================
with tab_hypotheses:
    st.header(lang["tab_hypotheses"])
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
# ABA 4: URLSCAN.IO
# =============================================================================
with tab_urlscan:
    st.header(lang["tab_urlscan"])
    st.caption("Submeta URLs suspeitas para verificação dinâmica, requisições HTTP e screenshots.")
    if URLSCAN_API_KEY:
        st.success("🔑 **Modo Autenticado:** usando sua API Key — cota completa de envios e buscas.")
    else:
        st.info("🆓 **Modo Anônimo Ativo (sem chave):** o urlscan.io permite enviar e buscar scans mesmo sem API Key, com cota menor e visibilidade pública.")
    target_scan_url = st.text_input("Insira a URL suspeita:", placeholder="https://exemplo-phishing.com", key="urlscan_target_input")
    pending_uuid = st.session_state.get("urlscan_pending_uuid")
    retry_scan = False
    if pending_uuid:
        col_scan_btn, col_retry_btn = st.columns([1, 1])
        start_scan = col_scan_btn.button("🚀 Enviar para urlscan.io", type="primary")
        retry_scan = col_retry_btn.button("🔄 Verificar Scan Pendente")
    else:
        start_scan = st.button("🚀 Enviar para urlscan.io", type="primary")
    if start_scan:
        if not target_scan_url or not target_scan_url.strip():
            st.warning("Informe uma URL antes de iniciar o scan.")
        else:
            submission = submit_urlscan(target_scan_url)
            if "error" in submission:
                st.error(submission["error"])
                st.session_state.pop("urlscan_pending_uuid", None)
            else:
                scan_uuid = submission.get("uuid")
                st.session_state["urlscan_pending_uuid"] = scan_uuid
                st.session_state["urlscan_pending_target"] = target_scan_url
                status_placeholder = st.empty()
                progress_bar = st.progress(0.0)
                with st.spinner("Aguardando o urlscan.io finalizar a análise..."):
                    result = poll_urlscan_result(scan_uuid, status_placeholder=status_placeholder, progress_bar=progress_bar)
                status_placeholder.empty()
                progress_bar.empty()
                if isinstance(result, dict) and result.get("error") == "timeout":
                    report_link = f"https://urlscan.io/result/{scan_uuid}/"
                    st.warning("O scan ainda está em processamento. Clique em '🔄 Verificar Scan Pendente' ou acompanhe: " + report_link)
                elif isinstance(result, dict) and "error" in result:
                    st.error(f"Falha ao obter o resultado: {result['error']}")
                else:
                    st.success("✅ Scan concluído com sucesso!")
                    st.session_state["urlscan_last_result"] = result
                    st.session_state["urlscan_last_target"] = target_scan_url
                    st.session_state.pop("urlscan_pending_uuid", None)
    elif retry_scan and pending_uuid:
        with st.spinner("Consultando o status do scan..."):
            result = get_urlscan_result(pending_uuid)
        if isinstance(result, dict) and result.get("__pending__"):
            st.info("⏳ O scan ainda está em processamento. Tente novamente em alguns segundos.")
        elif isinstance(result, dict) and "error" in result:
            st.error(f"Falha ao obter o resultado: {result['error']}")
        else:
            st.success("✅ Scan concluído com sucesso!")
            st.session_state["urlscan_last_result"] = result
            st.session_state["urlscan_last_target"] = st.session_state.get("urlscan_pending_target", target_scan_url)
            st.session_state.pop("urlscan_pending_uuid", None)
    if st.session_state.get("urlscan_last_result"):
        st.divider()
        render_urlscan_report(st.session_state["urlscan_last_result"], st.session_state.get("urlscan_last_target", target_scan_url))

# =============================================================================
# ABA 5: GREYNOISE
# =============================================================================
with tab_greynoise:
    st.header(lang["tab_greynoise"])
    st.caption("Descubra se o IP examinado é um scanner inofensivo conhecido, botnet ou IP malicioso.")
    if not GREYNOISE_API_KEY:
        st.info("ℹ️ **Modo Comunitário Gratuito Ativo:** Exibindo dados básicos. Adicione uma API Key na barra lateral para habilitar todos os campos enriquecidos.")
    else:
        st.success("🔑 **Modo Autenticado Business/Enterprise Ativo:** Trazendo contexto completo de inteligência.")
    gn_ip = st.text_input("Insira o endereço IP para consulta no GreyNoise:", placeholder="8.8.8.8", key="gn_ip_input")
    if st.button("Consultar GreyNoise", type="primary"):
        if gn_ip:
            gn_ip = gn_ip.strip()
            if not is_valid_ipv4(gn_ip):
                st.error("Informe um endereço IPv4 válido.")
            else:
                with st.spinner("Consultando GreyNoise..."):
                    gn_res = check_greynoise(gn_ip)
                    if "error" in gn_res:
                        st.error(gn_res["error"])
                    elif "message" in gn_res:
                        st.warning(gn_res["message"])
                    else:
                        render_greynoise_report(gn_res, gn_ip)

# =============================================================================
# ABA 6: VAZAMENTO-EMAIL (XposedOrNot)
# =============================================================================
with tab_vazamento:
    st.header(lang["tab_vazamento"])
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
                    raw_breaches = res.get("ExposedBreaches") or res.get("exposedBreaches") or []
                    if isinstance(raw_breaches, dict):
                        breaches_list = raw_breaches.get("breaches_details") or raw_breaches.get("breaches") or raw_breaches.get("details") or []
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
# ABA 7: APT-HUNTER & OSINT
# =============================================================================
with tab_osint:
    st.header(lang["tab_osint"])
    st.caption("Consulta unificada: informe um IP, domínio, URL, hash, e-mail ou CVE e a aplicação executará todas as integrações compatíveis.")
    st.info("A consulta automática usa somente integrações que realmente retornam dados: VirusTotal, AbuseIPDB, GreyNoise, urlscan.io, Shodan InternetDB, ip-api.com, BotScout, XposedOrNot.")
    query_value = st.text_input("🔎 Indicador para investigação:", placeholder="Ex.: 8.8.8.8 | exemplo.com | https://exemplo.com | SHA256 | usuario@empresa.com | CVE-2024-21410", key="osint_unified_query")
    auto_kind = detect_osint_query_type(query_value)
    st.caption(f"Tipo detectado automaticamente: **{auto_kind}**")
    q1, q2 = st.columns([1, 1])
    with q1:
        query_mode = st.selectbox("Modo de consulta", ["Automático", "IP", "Domínio", "URL", "Hash", "E-mail", "CVE/Termo"], key="osint_query_mode")
    with q2:
        st.markdown("**Fontes automáticas**")
        st.caption("O sistema só dispara uma fonte quando ela aceita o tipo do indicador informado.")
    if st.button("🚀 Consultar Todas as Fontes Compatíveis", type="primary", key="run_osint_unified"):
        raw = (query_value or "").strip()
        if not raw:
            st.warning("Informe um indicador para começar a investigação.")
        else:
            mode_map = {"Automático": auto_kind, "IP": "IP", "Domínio": "DOMAIN", "URL": "URL", "Hash": "SHA256" if re.fullmatch(r"[0-9a-fA-F]{64}", raw) else auto_kind, "E-mail": "EMAIL", "CVE/Termo": "CVE"}
            kind = mode_map.get(query_mode, auto_kind)
            if kind == "IP" and not is_valid_ipv4(raw):
                st.error("Informe um IPv4 válido.")
            else:
                with st.spinner("Consultando as fontes compatíveis em paralelo..."):
                    futures = {}
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        if kind in {"IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"}:
                            futures["VirusTotal"] = executor.submit(query_vt_universal, raw, kind)
                        if kind == "IP":
                            futures["AbuseIPDB"] = executor.submit(check_abuseipdb, raw)
                            futures["GreyNoise"] = executor.submit(check_greynoise, raw)
                            futures["urlscan"] = executor.submit(query_urlscan_universal, raw, kind)
                            futures["Shodan InternetDB"] = executor.submit(check_shodan_internetdb, raw)
                            futures["ip-api.com"] = executor.submit(check_ip_api_geo, raw)
                            futures["BotScout"] = executor.submit(check_botscout_ip, raw)
                        elif kind in {"DOMAIN", "URL"}:
                            futures["urlscan"] = executor.submit(query_urlscan_universal, raw, kind)
                        if kind == "EMAIL":
                            futures["BotScout"] = executor.submit(check_botscout_email, raw)
                            futures["XposedOrNot"] = executor.submit(check_xposedornot_analytics, raw)
                        unified = {}
                        for source, future in futures.items():
                            try:
                                unified[source] = future.result(timeout=60)
                            except Exception as exc:
                                unified[source] = {"error": str(exc)}
                st.session_state["osint_unified_last"] = {"value": raw, "kind": kind, "results": unified}
    last = st.session_state.get("osint_unified_last")
    if last:
        st.divider()
        render_osint_unified_report(last["value"], last["kind"], last["results"])

# =============================================================================
# ABA 8: CROSS-INTEL
# =============================================================================
with tab_cross:
    st.header(lang["tab_cross"])
    st.caption("Consulte simultaneamente VirusTotal, AbuseIPDB, GreyNoise e urlscan.io para obter um contexto unificado da ameaça.")
    st.caption("🟢 GreyNoise, urlscan.io, Shodan InternetDB e ip-api.com funcionam mesmo sem chave. VT e AbuseIPDB exigem chave própria.")
    cross_ip = st.text_input("Insira o indicador para correlação:", placeholder="IP, domínio, URL, hash, e-mail ou CVE", key="cross_ip_input")
    cross_kind = detect_osint_query_type(cross_ip)
    st.caption(f"Tipo detectado: **{cross_kind}** · Para relatório completo multiprotocolo, use também a aba APT-Hunter & OSINT.")
    if st.button("🚀 Iniciar Correlação", type="primary"):
        cross_ip = (cross_ip or "").strip()
        if not cross_ip:
            st.warning("Informe um endereço IP antes de iniciar a correlação.")
        elif not is_valid_ipv4(cross_ip):
            st.error("Informe um endereço IPv4 válido.")
        else:
            with st.spinner("Consultando múltiplas fontes de inteligência..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {
                        "vt": executor.submit(lambda: parse_vt_details(get_vt_data("ip_addresses", cross_ip))),
                        "abuse": executor.submit(check_abuseipdb, cross_ip),
                        "gn": executor.submit(check_greynoise, cross_ip),
                        "urlscan": executor.submit(check_urlscan_by_ip, cross_ip),
                        "free_ctx": executor.submit(get_free_ip_context, cross_ip),
                    }
                    results = {}
                    for key, future in futures.items():
                        try:
                            results[key] = future.result(timeout=20)
                        except Exception as exc:
                            results[key] = {"error": str(exc)}
                vt_res = results["vt"] if isinstance(results["vt"], dict) else {}
                abuse_res = results["abuse"] if isinstance(results["abuse"], dict) else {}
                gn_res = results["gn"] if isinstance(results["gn"], dict) else {}
                urlscan_res = results["urlscan"] if isinstance(results["urlscan"], dict) else {}
                free_ctx = results["free_ctx"] if isinstance(results["free_ctx"], dict) else {}
            vt_verdict = vt_res.get("verdict", "N/A")
            vt_error = vt_res.get("error")
            vt_malicious = vt_res.get("malicious", 0)
            vt_suspicious = vt_res.get("suspicious", 0)
            vt_total_engines = vt_res.get("total_engines", 0)
            vt_country = vt_res.get("country", "N/D")
            vt_as_owner = vt_res.get("as_owner", "N/D")
            vt_asn = vt_res.get("asn", "N/D")
            vt_tags = vt_res.get("tags", "Sem tags")
            vt_last_seen = vt_res.get("last_analysis_human", "N/D")
            abuse_error = abuse_res.get("error")
            if abuse_error:
                abuse_score_num = None
                abuse_score_display = "Erro"
                abuse_isp = "N/A"
            else:
                abuse_score_num = abuse_res.get("score_raw", 0)
                abuse_score_display = abuse_res.get("score", "N/A")
                abuse_isp = abuse_res.get("isp", "N/A")
            gn_report = None
            if "error" in gn_res:
                gn_class_display = f"Erro: {gn_res['error']}"
                gn_actor = "N/A"
            elif "message" in gn_res:
                gn_class_display = "Não Catalogado (Limpo/Desconhecido)"
                gn_actor = "N/A"
            else:
                gn_report = extract_greynoise_report(gn_res)
                gn_class_display = str(gn_report.get("classification", "unknown")).upper()
                gn_actor = gn_report.get("actor", "Desconhecido")
            urlscan_error = urlscan_res.get("error")
            urlscan_scans = urlscan_res.get("scans", []) if not urlscan_error else []
            urlscan_total = urlscan_res.get("total", 0) if not urlscan_error else 0
            urlscan_malicious_count = urlscan_res.get("malicious_count", 0) if not urlscan_error else 0
            free_ctx_country = free_ctx.get("country", "N/D") if isinstance(free_ctx, dict) else "N/D"
            botscout_res = check_botscout_ip(cross_ip)
            risk_points = 0
            risk_reasons = []
            mitigating_factors = []
            additional_signals = []
            if vt_malicious > 0:
                risk_points += 2
                risk_reasons.append(f"VirusTotal: {vt_malicious}/{vt_total_engines} motores classificaram como malicioso")
            elif vt_suspicious > 0:
                risk_points += 1
                risk_reasons.append(f"VirusTotal: {vt_suspicious}/{vt_total_engines} motores classificaram como suspeito")
            if abuse_score_num is not None:
                if abuse_score_num >= 75:
                    risk_points += 2
                    risk_reasons.append(f"AbuseIPDB com confiança de abuso alta ({abuse_score_display})")
                elif abuse_score_num >= 25:
                    risk_points += 1
                    risk_reasons.append(f"AbuseIPDB com confiança de abuso moderada ({abuse_score_display})")
            if abuse_res.get("is_whitelisted"):
                mitigating_factors.append("AbuseIPDB: IP consta na whitelist (uso legítimo conhecido)")
            if abuse_res.get("top_categories"):
                cats = ", ".join(name for name, _ in abuse_res["top_categories"][:3])
                risk_reasons.append(f"AbuseIPDB — categorias mais reportadas: {cats}")
            if gn_report and gn_report.get("mode") == "full":
                gn_classification = (gn_report.get("classification") or "").lower()
                if gn_classification == "malicious":
                    risk_points += 2
                    risk_reasons.append("GreyNoise classificou o comportamento de rede como MALICIOUS")
                elif gn_classification == "suspicious":
                    risk_points += 1
                    risk_reasons.append("GreyNoise classificou o comportamento de rede como SUSPICIOUS")
                if any(t.get("recommend_block") for t in (gn_report.get("tags_detail") or []) if isinstance(t, dict)):
                    risk_points += 1
                    risk_reasons.append("GreyNoise sinalizou tags com bloqueio recomendado (recommend_block)")
                if gn_report.get("cves"):
                    risk_points += 1
                    risk_reasons.append(f"GreyNoise: IP associado à exploração das CVEs {', '.join(gn_report['cves'])}")
                if gn_report.get("found_business"):
                    risk_points = max(0, risk_points - 1)
                    mitigating_factors.append(f"GreyNoise RIOT: serviço empresarial legítimo conhecido ({gn_report.get('business_name', 'N/D')})")
                if gn_report.get("tor"):
                    additional_signals.append("🧅 Nó de saída Tor")
                if gn_report.get("vpn"):
                    additional_signals.append(f"🔒 VPN detectada ({gn_report.get('vpn_service') or 'serviço não identificado'})")
                if gn_report.get("bot"):
                    additional_signals.append("🤖 Tráfego associado a bot")
                if gn_report.get("spoofable"):
                    additional_signals.append("🎭 IP de origem 'spoofable' (fácil de forjar)")
            elif gn_class_display == "MALICIOUS":
                risk_points += 2
                risk_reasons.append("GreyNoise classificou como MALICIOUS")
            elif gn_class_display == "SUSPICIOUS":
                risk_points += 1
            if abuse_res.get("is_tor"):
                additional_signals.append("🧅 AbuseIPDB também reporta este IP como nó Tor")
            if not urlscan_error:
                if urlscan_malicious_count > 0:
                    risk_points += 2
                    risk_reasons.append(f"urlscan.io: {urlscan_malicious_count} scan(s) hospedados neste IP marcados como MALICIOSOS")
                elif urlscan_total > 0:
                    risk_reasons.append(f"urlscan.io: {urlscan_total} scan(s) históricos encontrados para páginas hospedadas neste IP (nenhum malicioso)")
            if isinstance(free_ctx, dict) and free_ctx.get("vulns"):
                risk_points += 1
                risk_reasons.append(f"Shodan InternetDB: IP expõe serviço(s) associados às CVEs {', '.join(free_ctx['vulns'][:5])}")
            if risk_points >= 4:
                risk_label, risk_color = "🔴 ALTO RISCO", "error"
            elif risk_points >= 2:
                risk_label, risk_color = "🟠 RISCO MODERADO", "warning"
            elif risk_points >= 1:
                risk_label, risk_color = "🟡 RISCO BAIXO / SINAIS ISOLADOS", "warning"
            else:
                risk_label, risk_color = "🟢 BAIXO RISCO / SEM SINAIS", "success"
            st.subheader("🎯 Resultado Consolidado")
            getattr(st, risk_color)(f"**{risk_label}** — IP `{cross_ip}`  ·  Pontuação de risco: `{risk_points}`")
            if risk_reasons:
                st.markdown("**⚠️ Motivos que elevam o risco:**")
                for reason in risk_reasons:
                    st.markdown(f"- {reason}")
            if mitigating_factors:
                st.markdown("**✅ Fatores atenuantes:**")
                for factor in mitigating_factors:
                    st.markdown(f"- {factor}")
            if additional_signals:
                st.caption("Sinais adicionais de contexto: " + " · ".join(additional_signals))
            st.markdown("### 🌍 Contexto de Rede & Geolocalização")
            gctx1, gctx2, gctx3 = st.columns(3)
            gctx1.metric("País (VirusTotal)", vt_country if not vt_error else "N/D")
            gctx2.metric("País (AbuseIPDB)", abuse_res.get("country_name") or abuse_res.get("country") or "N/D")
            gctx3.metric("País (GreyNoise)", gn_report.get("country") if gn_report and gn_report.get("mode") == "full" else "N/D")
            st.caption(f"🏢 AS Owner (VT): {vt_as_owner} (`{vt_asn}`)  ·  🏢 Organização (GreyNoise): {gn_report.get('organization') if gn_report and gn_report.get('mode') == 'full' else 'N/D'}  ·  🏢 ISP (AbuseIPDB): {abuse_isp}")
            col_c1, col_c2, col_c3 = st.columns(3)
            with col_c1:
                if vt_error:
                    st.error(f"**VirusTotal**\n\nFalha na consulta: {vt_error}")
                else:
                    st.info(f"**VirusTotal**\n\nVeredito: {vt_verdict}\n\nReputação: `{vt_res.get('score', 'N/A')}`\n\nAS: {vt_as_owner} (`{vt_asn}`)\n\nPaís: {vt_country}  ·  Última análise: {vt_last_seen}")
            with col_c2:
                if abuse_error:
                    st.error(f"**AbuseIPDB**\n\nFalha na consulta: {abuse_error}")
                else:
                    st.warning(f"**AbuseIPDB**\n\nScore de Abuso: {abuse_score_display}  ({abuse_res.get('reports', 0)} reports de {abuse_res.get('distinct_reporters', 0)} usuários)\n\nISP: {abuse_isp}  ·  Uso: {abuse_res.get('usage_type', 'N/D')}\n\nWhitelisted: {'Sim' if abuse_res.get('is_whitelisted') else 'Não'}  ·  Último report: {abuse_res.get('last_reported_at', 'N/D')}")
            with col_c3:
                if "error" in gn_res:
                    st.error(f"**GreyNoise**\n\nFalha na consulta: {gn_res['error']}")
                elif "message" in gn_res:
                    st.info(f"**GreyNoise**\n\n{gn_res['message']}")
                elif gn_report and gn_report.get("mode") == "full":
                    st.error(f"**GreyNoise**\n\nClassificação: {gn_class_display}\n\nAtor: {gn_actor}  ·  Organização: {gn_report.get('organization', 'N/D')}\n\nRIOT (Serviço Confiável): {'Sim' if gn_report.get('found_business') else 'Não'}\n\nÚltima Atividade: {gn_report.get('last_seen', 'N/D')}")
                else:
                    st.error(f"**GreyNoise**\n\nClassificação: {gn_class_display}\n\nAtor: {gn_actor}")
            st.markdown("### 📋 Tabela de Atributos Cruzados")
            gn_tags_text = "Sem tags"
            gn_last_seen_text = "N/D"
            gn_score_text = "N/D"
            gn_country_text = "N/D"
            gn_org_text = "N/D"
            if gn_report and gn_report.get("mode") == "full":
                tag_bits = list(gn_report.get("tags") or [])
                if gn_report.get("cves"):
                    tag_bits += [f"CVE:{c}" for c in gn_report["cves"]]
                gn_tags_text = ", ".join(tag_bits) if tag_bits else "Sem tags"
                gn_last_seen_text = gn_report.get("last_seen", "N/D")
                gn_score_text = f"Trust Level: {gn_report.get('business_trust_level', 'N/D')}" if gn_report.get("found_business") else ("Noise: Sim" if gn_report.get("found_scanner") else "Sem classificação")
                gn_country_text = gn_report.get("country", "N/D")
                gn_org_text = f"{gn_report.get('organization', 'N/D')} (`{gn_report.get('asn', 'N/D')}`)"
            elif gn_report:
                gn_last_seen_text = gn_report.get("last_seen", "N/D")
                gn_score_text = "Noise: Sim" if gn_report.get("found_scanner") else "Noise: Não"
            abuse_tags_bits = []
            if not abuse_error:
                if abuse_res.get("domain") and abuse_res.get("domain") != "N/D":
                    abuse_tags_bits.append(f"domínio: {abuse_res['domain']}")
                if abuse_res.get("top_categories"):
                    abuse_tags_bits.append("categorias: " + ", ".join(n for n, _ in abuse_res["top_categories"][:3]))
                if abuse_res.get("is_tor"):
                    abuse_tags_bits.append("Tor")
            cross_data = {
                "Fonte": ["VirusTotal", "AbuseIPDB", "GreyNoise"],
                "Veredito / Classificação": [vt_verdict if not vt_error else f"Erro: {vt_error}", abuse_score_display if not abuse_error else f"Erro: {abuse_error}", gn_class_display],
                "Score / Confiança": [f"{vt_malicious}/{vt_total_engines} motores" if not vt_error else "N/A", f"{abuse_res.get('reports', 'N/A')} reports" if not abuse_error else "N/A", gn_score_text],
                "País": [vt_country if not vt_error else "N/D", (abuse_res.get("country_name") or abuse_res.get("country") or "N/D") if not abuse_error else "N/D", gn_country_text],
                "Organização / ISP / AS": [f"{vt_as_owner} ({vt_asn})" if not vt_error else "N/D", abuse_isp if not abuse_error else "N/D", gn_org_text],
                "Tags / Contexto Adicional": [vt_tags, ", ".join(abuse_tags_bits) if abuse_tags_bits else "—", gn_tags_text],
                "Última Atividade": [vt_last_seen if not vt_error else "N/D", abuse_res.get("last_reported_at", "N/D") if not abuse_error else "N/D", gn_last_seen_text],
            }
            st.dataframe(pd.DataFrame(cross_data), use_container_width=True, hide_index=True)
            st.markdown("### 🤖 Novas Fontes Correlacionadas")
            nc1, nc2 = st.columns(2)
            with nc1:
                if "error" in botscout_res:
                    st.error(f"**BotScout**\n\n{botscout_res['error']}")
                else:
                    matched = botscout_res.get("matched")
                    label = "🚨 Encontrado" if matched else ("✅ Não encontrado" if matched is not None else "⚪ Sem avaliação")
                    st.info(f"**BotScout**\n\nResultado: {label}\n\nCorrespondências: `{botscout_res.get('count', 'N/D')}`")
            with nc2:
                st.caption("AttackerKB removido conforme solicitado.")
            if vt_res.get("malicious_engines"):
                st.caption("🧪 Motores AV que sinalizaram este IP no VirusTotal: " + ", ".join(vt_res["malicious_engines"]))
            st.markdown("### 🔗 Links Diretos")
            link_col1, link_col2, link_col3 = st.columns(3)
            link_col1.link_button("Abrir no VirusTotal", f"https://www.virustotal.com/gui/ip-address/{cross_ip}")
            link_col2.link_button("Abrir no AbuseIPDB", f"https://www.abuseipdb.com/check/{cross_ip}")
            link_col3.link_button("Abrir no GreyNoise", f"https://viz.greynoise.io/ip/{cross_ip}")
            with st.expander("🔍 Ver respostas brutas (JSON) para depuração"):
                st.json({"virustotal": vt_res, "abuseipdb": abuse_res, "greynoise": gn_res})

# =============================================================================
# NOVA ABA: THREAT INTEL MANUAL (Hybrid Analysis & MISP)
# =============================================================================
with tab_manual:
    st.header("🧰 Threat Intel Manual")
    st.markdown("""
        Nesta seção, você pode realizar consultas manuais em plataformas que não possuem API pública gratuita
        ou exigem autenticação. Utilize os links abaixo para acessar diretamente as interfaces web e obter
        relatórios úteis para o caçador de ameaças.
    """)

    col_ha, col_misp = st.columns(2)

    with col_ha:
        st.subheader("🔬 Hybrid Analysis")
        st.write("""
            **Hybrid Analysis** é uma sandbox gratuita da CrowdStrike que analisa arquivos e URLs em busca de comportamento malicioso.
            - **Sem API key**: você pode usar o site para enviar amostras manualmente ou pesquisar por hash/URL.
            - **Dica**: após obter o hash de um arquivo, use a busca pública para ver relatórios detalhados.
        """)
        st.markdown("[Abrir Hybrid Analysis](https://www.hybrid-analysis.com/)")
        ha_hash = st.text_input("Hash para pesquisa rápida (cole e pressione Enter para abrir o site):", key="ha_hash_manual")
        if ha_hash:
            st.markdown(f"[Pesquisar no Hybrid Analysis](https://www.hybrid-analysis.com/search?query={ha_hash})")

    with col_misp:
        st.subheader("🛡️ MISP (Malware Information Sharing Platform)")
        st.write("""
            **MISP** é uma plataforma open-source de compartilhamento de inteligência de ameaças.
            - **Sem API key**: você pode acessar instâncias públicas como o **CIRCL MISP** (https://www.circl.lu/services/misp/) ou comunidades abertas.
            - Muitas organizações disponibilizam feeds públicos que podem ser consultados manualmente.
            - Se você possui uma instância MISP própria, configure a URL e chave na barra lateral (não implementado aqui, mas você pode adaptar).
        """)
        st.markdown("[Abrir CIRCL MISP (público)](https://www.circl.lu/services/misp/)")
        misp_indicator = st.text_input("Indicador para busca manual (ex: IP, domínio, hash):", key="misp_indicator_manual",
                                       help="Copie e cole no campo de busca do MISP após abrir o link.")
        if misp_indicator:
            st.info(f"Indicador: `{misp_indicator}`")

    st.divider()
    st.info("💡 **Nota:** As consultas manuais dependem de acesso externo e não estão integradas automaticamente. Use os links para obter relatórios completos.")

# -----------------------------------------------------------------------------
# 8. RODAPÉ
# -----------------------------------------------------------------------------
st.markdown(f"""
    <div class="footer-text">
        {lang["footer"]}
    </div>
""", unsafe_allow_html=True)
