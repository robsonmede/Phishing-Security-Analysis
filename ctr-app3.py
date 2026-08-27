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
    page_title="Cyber Threat Research - Caçador de Ameaças V2.9",
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
def get_secret(name):
    """Obtém um segredo sem derrubar a aplicação quando secrets.toml não existe."""
    try:
        return st.secrets.get(name, "")
    except Exception:
        return ""

with st.sidebar:
    st.markdown("### 🔑 Credenciais API")

    def_vt = get_secret("VIRUSTOTAL_API_KEY")
    def_abuse = get_secret("ABUSEIPDB_API_KEY")
    def_urlscan = get_secret("URLSCAN_API_KEY")
    def_greynoise = get_secret("GREYNOISE_API_KEY")

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
st.markdown('<div class="main-header">🛡️ Cyber Threat Research - Caçador de Ameaças V2.9</div>', unsafe_allow_html=True)
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

def is_valid_ipv4(ip_address):
    """Valida IPv4 para evitar consultas inválidas às APIs."""
    try:
        return ipaddress.ip_address(ip_address).version == 4
    except ValueError:
        return False


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

        # Motores AV/engines que sinalizaram o indicador (útil para IPs e hashes)
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
# Categorias oficiais de report do AbuseIPDB (id -> nome), usadas para resumir os motivos dos reports.
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

            # Resume as categorias mais reportadas a partir dos reports individuais (modo verbose)
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
        # API v3 autenticada: /v3/ip/{ip}
        url = f"https://api.greynoise.io/v3/ip/{ip_address}"
        headers = {"Accept": "application/json", "key": GREYNOISE_API_KEY}
    else:
        # Community API: /v3/community/{ip}
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
    """Normaliza 'internet_scanner_intelligence.tags': lista de objetos {name, slug, ...} na API completa."""
    names = []
    for t in tags or []:
        if isinstance(t, dict):
            names.append(t.get("name") or t.get("slug") or "Tag")
        else:
            names.append(str(t))
    return names


def extract_greynoise_report(gn_res):
    """Normaliza a resposta do GreyNoise em uma estrutura única para renderização.

    A API v3 autenticada (Business/Enterprise) devolve os dados aninhados em
    'internet_scanner_intelligence' e 'business_service_intelligence'; a Community API
    (sem chave) devolve um payload achatado (ip, noise, riot, classification...).
    Tratamos os dois formatos para não quebrar a exibição conforme o modo de acesso.
    """
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

    # Community API (payload achatado)
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
    """Renderiza um relatório rico do GreyNoise: classificação, comportamento de rede,
    tags com contexto, CVEs, alvos de escaneamento e (quando disponível) o serviço
    de negócio legítimo por trás do IP — em vez de apenas alguns campos soltos."""
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

    # --- Modo completo (Business/Enterprise) ---
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
        st.markdown(f"**🌍 País de Origem:** {flag} `{report['country']}` ({report['region']})")
        st.markdown(f"**🏙️ Cidade:** `{report['city']}`")
        st.markdown(f"**📅 First Seen:** `{report['first_seen']}`  ·  **Last Seen:** `{report['last_seen']}`")
        st.markdown(f"**📡 Sensor Count:** `{report['sensor_count']}`  ·  **Sensor Hits:** `{report['sensor_hits']}`")

    st.divider()

    # --- Comportamento de rede ---
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

    # --- Tags & CVEs ---
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

    # --- Alvos do escaneamento (para onde este IP costuma apontar) ---
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

    # --- Business Service Intelligence (RIOT) ---
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
    """Envia uma URL para varredura assíncrona no urlscan.io.
    A submissão só retorna o UUID da tarefa: o resultado completo precisa
    ser consultado depois, via get_urlscan_result / poll_urlscan_result."""
    if not URLSCAN_API_KEY:
        return {"error": "Sem API Key"}

    target_url = target_url.strip()
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"error": "URL inválida. Use uma URL completa, por exemplo: https://exemplo.com"}

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    data = {"url": target_url, "visibility": "public"}

    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=data,
            timeout=15,
        )
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
            return {"error": "Limite de requisições do urlscan.io atingido. Aguarde antes de tentar novamente."}
        return {"error": f"HTTP {response.status_code}: {response.text[:500]}"}
    except requests.RequestException as exc:
        return {"error": f"Falha de comunicação com urlscan.io: {exc}"}


def get_urlscan_result(scan_uuid):
    """Consulta o resultado de um scan pelo UUID.
    Enquanto o scan ainda está em processamento, o urlscan.io responde HTTP 404;
    isso é sinalizado aqui como {'__pending__': True} para o chamador decidir se aguarda."""
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


def poll_urlscan_result(scan_uuid, status_placeholder=None, progress_bar=None,
                         initial_wait=15, poll_interval=5, max_wait=90):
    """Aguarda a finalização do scan seguindo a orientação oficial do urlscan.io:
    esperar alguns segundos após o envio e então consultar em intervalos curtos
    até finalizar ou atingir o tempo máximo de espera (evita martelar a API)."""

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
    """Percorre chaves aninhadas com segurança, tolerando dicionários ausentes/incompletos.
    Campos do urlscan.io (especialmente em data.requests) vêm do próprio Chrome
    e podem mudar de formato sem aviso — por isso tudo aqui é .get() defensivo."""
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
    """'verdicts.overall.brands' é uma lista de strings simples;
    'verdicts.urlscan.brands' é uma lista de objetos {name, key, ...}. Tratamos os dois formatos."""
    names = []
    for b in brands or []:
        if isinstance(b, str):
            names.append(b)
        elif isinstance(b, dict):
            names.append(b.get("name") or b.get("key") or "Desconhecido")
    return names


def extract_urlscan_verdict(result):
    """Classification: consolida o veredito de ameaça a partir de verdicts.overall / verdicts.urlscan."""
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
    """Summary: visão geral da página escaneada."""
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
    """Located / IP / AS: geolocalização e rede da requisição primária da página."""
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
    """Page URL History: cadeia de redirecionamentos da URL submetida até a URL final.
    Usa o campo oficial 'data.redirects' quando disponível; caso contrário, reconstrói
    a partir das requisições de navegação/3xx em 'data.requests' (sempre presentes)."""
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
    """HTTP Transactions: cada requisição/resposta feita durante o carregamento da página."""
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
    """Renderiza o relatório completo do scan: Summary, Located, IP, Classification,
    AS, Page URL History e HTTP Transactions — em vez do JSON bruto."""
    summary = extract_urlscan_summary(result)
    verdict = extract_urlscan_verdict(result)
    location = extract_urlscan_location(result)
    history = extract_urlscan_history(result)
    transactions = extract_urlscan_transactions(result)

    # --- Summary ---
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

    # --- Located / IP / AS ---
    st.markdown("### 📍 Localização (Located) & Rede")
    l1, l2, l3, l4 = st.columns(4)
    l1.info(f"**País**\n\n{location['flag']} {location['country']}")
    l2.info(f"**Cidade**\n\n{location['city']}")
    l3.info(f"**IP**\n\n`{location['ip']}`")
    l4.info(f"**AS (ASN)**\n\n`{location['asn']}`\n\n{location['asnname']}")
    st.caption(f"🖥️ Servidor (HTTP Server header): {location['server']}  ·  📛 PTR: {location['ptr']}")

    st.divider()

    # --- Page URL History ---
    st.markdown("### 🧭 Histórico de URL da Página (Page URL History)")
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
    else:
        st.caption("Nenhum redirecionamento detectado — a URL carregou diretamente.")

    st.divider()

    # --- HTTP Transactions ---
    st.markdown(f"### 📡 Transações HTTP (HTTP Transactions) — {len(transactions)} requisições capturadas")
    if transactions:
        df_tx = pd.DataFrame(transactions)
        filter_txt = st.text_input(
            "Filtrar transações por domínio/URL:",
            key="urlscan_tx_filter",
            placeholder="ex: googletagmanager.com",
        )
        if filter_txt:
            df_tx = df_tx[df_tx["URL"].str.contains(filter_txt, case=False, na=False, regex=False)]
        st.dataframe(df_tx, use_container_width=True, hide_index=True, height=380)
        st.download_button(
            "⬇️ Exportar Transações (CSV)",
            df_tx.to_csv(index=False).encode("utf-8"),
            file_name=f"urlscan_transactions_{urllib.parse.urlparse(target_scan_url).netloc or 'scan'}.csv",
            mime="text/csv",
        )
    else:
        st.caption("Nenhuma transação HTTP foi capturada para esta página.")

    # --- Screenshot (bônus, já prometido na descrição da aba) ---
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


# --- XposedOrNot Analytics ---
def check_xposedornot_analytics(email):
    email = email.strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return {"error": "Endereço de e-mail inválido."}

    try:
        res = requests.get(
            "https://api.xposedornot.com/v1/breach-analytics",
            params={"email": email},
            timeout=10,
        )
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
    tab_iocs,
    tab_hypotheses,
    tab_queries,
    tab_urlscan,
    tab_greynoise,
    tab_entropy,
    tab_email,
    tab_xposed,
    tab_cross_intel,
) = st.tabs([
    "🔍 Extrator & AbuseIP",
    "🎯 Central de Hipóteses",
    "🎯 SIEM Queries",
    "🌐 urlscan.io",
    "📡 GreyNoise",
    "📊 Entropia",
    "📧 Cabeçalho E-mail",
    "🔓 XposedOrNot",
    "🔗 Cross-Intel",
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

        ips = sorted({
            ip for ip in re.findall(ip_pattern, text)
            if is_valid_ipv4(ip)
        })
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
            items = [
                item.strip().strip(",")
                for item in ioc_values.splitlines()
                if item.strip()
            ]

            if not items:
                st.warning("Informe pelo menos um indicador.")
            elif "Sentinel" in siem_platform:
                quoted = ", ".join(f'"{i}"' for i in items)
                q = f"DeviceNetworkEvents | where RemoteIP in ({quoted})"
                st.code(q, language="kql")
            elif "Elasticsearch" in siem_platform:
                quoted = ", ".join(f'"{i}"' for i in items)
                q = f"network where destination.ip in ({quoted})"
                st.code(q, language="text")
            else:
                q = " OR ".join(f'domain:"{i}" OR ip:"{i}"' for i in items)
                st.code(q, language="text")

# =============================================================================
# ABA 4: URLSCAN.IO
# =============================================================================
with tab_urlscan:
    st.header("🌐 urlscan.io - Análise de URLs")
    st.caption("Submeta URLs suspeitas para verificação dinâmica, requisições HTTP e screenshots.")
    st.caption("ℹ️ O scan é assíncrono: leva em geral de ~15 a 60s para ser concluído, dependendo da complexidade da página.")

    target_scan_url = st.text_input(
        "Insira a URL suspeita:",
        placeholder="https://exemplo-phishing.com",
        key="urlscan_target_input",
    )

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
                    result = poll_urlscan_result(
                        scan_uuid,
                        status_placeholder=status_placeholder,
                        progress_bar=progress_bar,
                    )
                status_placeholder.empty()
                progress_bar.empty()

                if isinstance(result, dict) and result.get("error") == "timeout":
                    report_link = f"https://urlscan.io/result/{scan_uuid}/"
                    st.warning(
                        "O scan ainda está em processamento no urlscan.io após o tempo máximo de espera. "
                        f"Clique em **'🔄 Verificar Scan Pendente'** em alguns instantes, ou acompanhe direto por lá: {report_link}"
                    )
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
            st.info("⏳ O scan ainda está em processamento no urlscan.io. Tente novamente em alguns segundos.")
        elif isinstance(result, dict) and "error" in result:
            st.error(f"Falha ao obter o resultado: {result['error']}")
        else:
            st.success("✅ Scan concluído com sucesso!")
            st.session_state["urlscan_last_result"] = result
            st.session_state["urlscan_last_target"] = st.session_state.get("urlscan_pending_target", target_scan_url)
            st.session_state.pop("urlscan_pending_uuid", None)

    if st.session_state.get("urlscan_last_result"):
        st.divider()
        render_urlscan_report(
            st.session_state["urlscan_last_result"],
            st.session_state.get("urlscan_last_target", target_scan_url),
        )

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
            gn_ip = gn_ip.strip()
            if not is_valid_ipv4(gn_ip):
                st.error("Informe um endereço IPv4 válido.")
                st.stop()

            with st.spinner("Consultando GreyNoise..."):
                gn_res = check_greynoise(gn_ip)
                if "error" in gn_res:
                    st.error(gn_res["error"])
                elif "message" in gn_res:
                    st.warning(gn_res["message"])
                else:
                    render_greynoise_report(gn_res, gn_ip)

# =============================================================================
# ABA 6: CALCULADOR DE ENTROPIA
# =============================================================================
with tab_entropy:
    st.header("📊 Calculador de Entropia de Shannon")
    raw_str = st.text_area("Insira a String/Payload Base64 para cálculo de aleatoriedade:", height=100)
    if raw_str.strip():
        try:
            b_data = base64.b64decode(raw_str.strip(), validate=True)
            fonte = "Base64"
        except (ValueError, base64.binascii.Error):
            b_data = raw_str.encode("utf-8")
            fonte = "Texto"

        if b_data:
            counts = [0] * 256
            for byte in b_data:
                counts[byte] += 1

            entropy = -sum(
                (count / len(b_data)) * math.log2(count / len(b_data))
                for count in counts
                if count > 0
            )

            st.metric("Score de Entropia", f"{entropy:.4f} / 8.0")
            st.caption(f"Entrada interpretada como: {fonte} | {len(b_data)} bytes")

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
                    raw_breaches = res.get("ExposedBreaches") or res.get("exposedBreaches") or []

                    if isinstance(raw_breaches, dict):
                        breaches_list = (
                            raw_breaches.get("breaches_details")
                            or raw_breaches.get("breaches")
                            or raw_breaches.get("details")
                            or []
                        )
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

    cross_ip = st.text_input(
        "Insira o Endereço IP para correlação:",
        placeholder="1.1.1.1",
        key="cross_ip_input",
    )

    if st.button("🚀 Iniciar Correlação", type="primary"):
        cross_ip = (cross_ip or "").strip()

        if not cross_ip:
            st.warning("Informe um endereço IP antes de iniciar a correlação.")
        elif not is_valid_ipv4(cross_ip):
            st.error("Informe um endereço IPv4 válido.")
        else:
            with st.spinner("Consultando múltiplas fontes de inteligência..."):
                # Chamadas em paralelo para reduzir o tempo total de espera
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                    futures = {
                        "vt": executor.submit(lambda: parse_vt_details(get_vt_data("ip_addresses", cross_ip))),
                        "abuse": executor.submit(check_abuseipdb, cross_ip),
                        "gn": executor.submit(check_greynoise, cross_ip),
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

            # --- Normalização dos resultados ---
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

            # --- Score de risco consolidado (heurística com múltiplos sinais) ---
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
                    mitigating_factors.append(
                        f"GreyNoise RIOT: serviço empresarial legítimo conhecido ({gn_report.get('business_name', 'N/D')})"
                    )

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

            # --- Contexto de rede consolidado (comparação rápida entre fontes) ---
            st.markdown("### 🌍 Contexto de Rede & Geolocalização")
            gctx1, gctx2, gctx3 = st.columns(3)
            gctx1.metric("País (VirusTotal)", vt_country if not vt_error else "N/D")
            gctx2.metric("País (AbuseIPDB)", abuse_res.get("country_name") or abuse_res.get("country") or "N/D")
            gctx3.metric("País (GreyNoise)", gn_report.get("country") if gn_report and gn_report.get("mode") == "full" else "N/D")
            st.caption(
                f"🏢 AS Owner (VT): {vt_as_owner} (`{vt_asn}`)  ·  "
                f"🏢 Organização (GreyNoise): {gn_report.get('organization') if gn_report and gn_report.get('mode') == 'full' else 'N/D'}  ·  "
                f"🏢 ISP (AbuseIPDB): {abuse_isp}"
            )

            col_c1, col_c2, col_c3 = st.columns(3)
            with col_c1:
                if vt_error:
                    st.error(f"**VirusTotal**\n\nFalha na consulta: {vt_error}")
                else:
                    st.info(
                        f"**VirusTotal**\n\n"
                        f"Veredito: {vt_verdict}\n\n"
                        f"Reputação: `{vt_res.get('score', 'N/A')}`\n\n"
                        f"AS: {vt_as_owner} (`{vt_asn}`)\n\n"
                        f"País: {vt_country}  ·  Última análise: {vt_last_seen}"
                    )
            with col_c2:
                if abuse_error:
                    st.error(f"**AbuseIPDB**\n\nFalha na consulta: {abuse_error}")
                else:
                    st.warning(
                        f"**AbuseIPDB**\n\n"
                        f"Score de Abuso: {abuse_score_display}  ({abuse_res.get('reports', 0)} reports de "
                        f"{abuse_res.get('distinct_reporters', 0)} usuários)\n\n"
                        f"ISP: {abuse_isp}  ·  Uso: {abuse_res.get('usage_type', 'N/D')}\n\n"
                        f"Whitelisted: {'Sim' if abuse_res.get('is_whitelisted') else 'Não'}  ·  "
                        f"Último report: {abuse_res.get('last_reported_at', 'N/D')}"
                    )
            with col_c3:
                if "error" in gn_res:
                    st.error(f"**GreyNoise**\n\nFalha na consulta: {gn_res['error']}")
                elif "message" in gn_res:
                    st.info(f"**GreyNoise**\n\n{gn_res['message']}")
                elif gn_report and gn_report.get("mode") == "full":
                    st.error(
                        f"**GreyNoise**\n\n"
                        f"Classificação: {gn_class_display}\n\n"
                        f"Ator: {gn_actor}  ·  Organização: {gn_report.get('organization', 'N/D')}\n\n"
                        f"RIOT (Serviço Confiável): {'Sim' if gn_report.get('found_business') else 'Não'}\n\n"
                        f"Última Atividade: {gn_report.get('last_seen', 'N/D')}"
                    )
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
                "Veredito / Classificação": [
                    vt_verdict if not vt_error else f"Erro: {vt_error}",
                    abuse_score_display if not abuse_error else f"Erro: {abuse_error}",
                    gn_class_display,
                ],
                "Score / Confiança": [
                    f"{vt_malicious}/{vt_total_engines} motores" if not vt_error else "N/A",
                    f"{abuse_res.get('reports', 'N/A')} reports" if not abuse_error else "N/A",
                    gn_score_text,
                ],
                "País": [
                    vt_country if not vt_error else "N/D",
                    (abuse_res.get("country_name") or abuse_res.get("country") or "N/D") if not abuse_error else "N/D",
                    gn_country_text,
                ],
                "Organização / ISP / AS": [
                    f"{vt_as_owner} ({vt_asn})" if not vt_error else "N/D",
                    abuse_isp if not abuse_error else "N/D",
                    gn_org_text,
                ],
                "Tags / Contexto Adicional": [
                    vt_tags,
                    ", ".join(abuse_tags_bits) if abuse_tags_bits else "—",
                    gn_tags_text,
                ],
                "Última Atividade": [
                    vt_last_seen if not vt_error else "N/D",
                    abuse_res.get("last_reported_at", "N/D") if not abuse_error else "N/D",
                    gn_last_seen_text,
                ],
            }
            st.dataframe(pd.DataFrame(cross_data), use_container_width=True, hide_index=True)

            if vt_res.get("malicious_engines"):
                st.caption("🧪 Motores AV que sinalizaram este IP no VirusTotal: " + ", ".join(vt_res["malicious_engines"]))

            st.markdown("### 🔗 Links Diretos")
            link_col1, link_col2, link_col3 = st.columns(3)
            link_col1.link_button("Abrir no VirusTotal", f"https://www.virustotal.com/gui/ip-address/{cross_ip}")
            link_col2.link_button("Abrir no AbuseIPDB", f"https://www.abuseipdb.com/check/{cross_ip}")
            link_col3.link_button("Abrir no GreyNoise", f"https://viz.greynoise.io/ip/{cross_ip}")

            with st.expander("🔍 Ver respostas brutas (JSON) para depuração"):
                st.json({"virustotal": vt_res, "abuseipdb": abuse_res, "greynoise": gn_res})

# -----------------------------------------------------------------------------
# 8. RODAPÉ
# -----------------------------------------------------------------------------
st.markdown("""
    <div class="footer-text">
        CTRDEFENSE.BLOG &copy; 2026 | Cyber Threat Research - Caçador de Ameaças V2.9
    </div>
""", unsafe_allow_html=True)
