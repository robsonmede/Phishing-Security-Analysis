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
# 6. MÓDULOS DE INTEGRAÇÃO (mantidos do código anterior, sem Cuckoo)
# -----------------------------------------------------------------------------
# (Todo o código de funções: is_valid_ipv4, render_country_field, check_shodan_internetdb,
# check_ip_api_geo, get_free_ip_context, get_vt_data, parse_vt_details, check_abuseipdb,
# check_greynoise, extract_greynoise_report, render_greynoise_report, submit_urlscan,
# search_urlscan, check_urlscan_by_ip, get_urlscan_result, poll_urlscan_result, _dig,
# _country_flag, _format_scan_datetime, _brand_names, extract_urlscan_verdict,
# extract_urlscan_summary, extract_urlscan_location, extract_urlscan_history,
# extract_urlscan_transactions, render_urlscan_report, check_botscout_ip, check_botscout_email,
# detect_osint_query_type, vt_url_id, query_vt_universal, query_urlscan_universal,
# render_osint_unified_report, check_xposedornot_analytics)
# permanece idêntico ao fornecido anteriormente. Por brevidade, não repetirei aqui,
# mas assuma que está presente no código final.)

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
    tab_manual,  # Nova aba
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
    raw_text = st.text_area("Cole os IOCs para análise:", height=120)
    # ... (restante do código da aba extrator permanece igual)

# =============================================================================
# ABA 2: ABUSEIPDB
# =============================================================================
with tab_abuseipdb:
    st.header(lang["tab_abuseipdb"])
    # ...

# =============================================================================
# ABA 3: CENTRAL DE HIPÓTESES
# =============================================================================
with tab_hypotheses:
    st.header(lang["tab_hypotheses"])
    # ...

# =============================================================================
# ABA 4: URLSCAN.IO
# =============================================================================
with tab_urlscan:
    st.header(lang["tab_urlscan"])
    # ...

# =============================================================================
# ABA 5: GREYNOISE
# =============================================================================
with tab_greynoise:
    st.header(lang["tab_greynoise"])
    # ...

# =============================================================================
# ABA 6: VAZAMENTO-EMAIL
# =============================================================================
with tab_vazamento:
    st.header(lang["tab_vazamento"])
    # ...

# =============================================================================
# ABA 7: APT-HUNTER & OSINT
# =============================================================================
with tab_osint:
    st.header(lang["tab_osint"])
    # ...

# =============================================================================
# ABA 8: CROSS-INTEL
# =============================================================================
with tab_cross:
    st.header(lang["tab_cross"])
    # ...

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
        st.text_input("Hash para pesquisa rápida (cole e pressione Enter para abrir o site):", key="ha_hash_manual",
                      on_change=lambda: st.markdown(f"[Pesquisar no Hybrid Analysis](https://www.hybrid-analysis.com/search?query={st.session_state.ha_hash_manual})"))

    with col_misp:
        st.subheader("🛡️ MISP (Malware Information Sharing Platform)")
        st.write("""
            **MISP** é uma plataforma open-source de compartilhamento de inteligência de ameaças.
            - **Sem API key**: você pode acessar instâncias públicas como o **CIRCL MISP** (https://www.circl.lu/services/misp/) ou comunidades abertas.
            - Muitas organizações disponibilizam feeds públicos que podem ser consultados manualmente.
            - Se você possui uma instância MISP própria, configure a URL e chave na barra lateral (não implementado aqui, mas você pode adaptar).
        """)
        st.markdown("[Abrir CIRCL MISP (público)](https://www.circl.lu/services/misp/)")
        st.text_input("Indicador para busca manual (ex: IP, domínio, hash):", key="misp_indicator_manual",
                      help="Copie e cole no campo de busca do MISP após abrir o link.")

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
