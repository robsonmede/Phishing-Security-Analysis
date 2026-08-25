import re
import urllib.parse
import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Toolkit - CTRDEFENSE.BLOG",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Analyst Toolkit")
st.caption("Desenvolvido para otimizar triagens e análises do time de Segurança da Informação.")

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA API DO VIRUSTOTAL
# -----------------------------------------------------------------------------
VT_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")

def get_vt_data(endpoint, item_id):
    """Realiza requisições genéricas à API v3 do VirusTotal."""
    if not VT_API_KEY:
        return {"error": "API Key não configurada"}

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{item_id}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Não encontrado no VirusTotal"}
        elif response.status_code == 401:
            return {"error": "API Key Inválida"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def parse_vt_stats(vt_response):
    """Extrai estatísticas de detecção de uma resposta do VirusTotal."""
    if "error" in vt_response:
        return f"⚠️ {vt_response['error']}"
    
    try:
        stats = vt_response["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        if malicious > 0:
            return f"🚨 {malicious}/{total} Detecções Maliciosas"
        return f"✅ {malicious}/{total} (Limpo)"
    except KeyError:
        return "N/D"

# -----------------------------------------------------------------------------
# MENU LATERAL DE NAVEGAÇÃO
# -----------------------------------------------------------------------------
st.sidebar.header("⚙️ Navegação")
menu_option = st.sidebar.radio(
    "Escolha a Ferramenta:",
    [
        "📧 Analisador de Cabeçalho de E-mail",
        "🔍 Extrator, Defang e Consulta VT (IOCs)"
    ]
)

st.sidebar.divider()
if VT_API_KEY:
    st.sidebar.success("🔑 API Key do VirusTotal conectada!")
else:
    st.sidebar.warning("⚠️ API Key do VirusTotal não detectada nos Secrets.")

# =============================================================================
# FERRAMENTA 1: ANALISADOR DE CABEÇALHO DE E-MAIL
# =============================================================================
if menu_option == "📧 Analisador de Cabeçalho de E-mail":
    st.header("📧 Analisador de Cabeçalhos de E-mail (Phishing)")
    st.caption("Extraia autenticações SPF/DKIM/DMARC e rastreie os saltos de rede de e-mails suspeitos.")

    raw_header = st.text_area("Cole o cabeçalho bruto do e-mail (Raw Header) aqui:", height=200)

    def parse_authentication(header_text):
        auth_results = {"SPF": "Não encontrado", "DKIM": "Não encontrado", "DMARC": "Não encontrado"}
        spf_match = re.search(r'spf=(\w+)', header_text, re.IGNORECASE)
        dkim_match = re.search(r'dkim=(\w+)', header_text, re.IGNORECASE)
        dmarc_match = re.search(r'dmarc=(\w+)', header_text, re.IGNORECASE)

        if spf_match: auth_results["SPF"] = spf_match.group(1).upper()
        if dkim_match: auth_results["DKIM"] = dkim_match.group(1).upper()
        if dmarc_match: auth_results["DMARC"] = dmarc_match.group(1).upper()
        return auth_results

    def parse_hops(header_text):
        hops = []
        received_lines = re.findall(r'Received:\s*from\s+(.*?)(?=\n\S|\Z)', header_text, re.DOTALL | re.IGNORECASE)
        for i, line in enumerate(received_lines, start=1):
            clean_line = " ".join(line.split())
            hops.append({"Salto (#)": i, "Detalhes do Servidor / IP": clean_line[:120] + "..." if len(clean_line) > 120 else clean_line})
        return pd.DataFrame(hops)

    if st.button("Analisar Cabeçalho", type="primary"):
        if not raw_header.strip():
            st.warning("Por favor, cole um cabeçalho válido antes de analisar.")
        else:
            st.subheader("1. Status das Autenticações")
            auth_data = parse_authentication(raw_header)
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Status SPF", auth_data["SPF"], 
                          delta="PASS" if auth_data["SPF"] == "PASS" else "-FAIL/ALERT",
                          delta_color="normal" if auth_data["SPF"] == "PASS" else "inverse")
            with col2:
                st.metric("Status DKIM", auth_data["DKIM"], 
                          delta="PASS" if auth_data["DKIM"] == "PASS" else "-FAIL/ALERT",
                          delta_color="normal" if auth_data["DKIM"] == "PASS" else "inverse")
            with col3:
                st.metric("Status DMARC", auth_data["DMARC"], 
                          delta="PASS" if auth_data["DMARC"] == "PASS" else "-FAIL/ALERT",
                          delta_color="normal" if auth_data["DMARC"] == "PASS" else "inverse")

            st.divider()
            st.subheader("2. Rota de Saltos de Rede (Network Hops)")
            df_hops = parse_hops(raw_header)
            if not df_hops.empty:
                st.dataframe(df_hops, use_container_width=True)
            else:
                st.info("Nenhuma linha 'Received:' foi identificada.")

# =============================================================================
# FERRAMENTA 2: EXTRATOR, DEFANG E CONSULTA VIRUSTOTAL DE IOCS
# =============================================================================
elif menu_option == "🔍 Extrator, Defang e Consulta VT (IOCs)":
    st.header("🔍 Extrator de IOCs e Consulta em Tempo Real no VirusTotal")
    st.caption("Extraia IPs, URLs e Hashes, aplique Defang e consulte a reputação diretamente via API v3 do VirusTotal.")

    raw_text = st.text_area("Cole o texto bruto (logs, alertas, relatórios, hashes) aqui:", height=200)

    def defang(value):
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

    def extract_iocs(text):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

        ips = list(set(re.findall(ip_pattern, text)))
        urls = list(set(re.findall(url_pattern, text)))
        emails = list(set(re.findall(email_pattern, text)))
        md5s = list(set(re.findall(md5_pattern, text)))
        sha256s = list(set(re.findall(sha256_pattern, text)))

        return ips, urls, emails, md5s, sha256s

    if st.button("Extrair e Enriquecer IOCs", type="primary"):
        if not raw_text.strip():
            st.warning("Por favor, cole algum texto antes de executar a análise.")
        else:
            ips, urls, emails, md5s, sha256s = extract_iocs(raw_text)

            st.subheader("📊 Resumo dos Indicadores Encontrados")
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("IPs (v4)", len(ips))
            m2.metric("URLs", len(urls))
            m3.metric("E-mails", len(emails))
            m4.metric("Hashes MD5", len(md5s))
            m5.metric("Hashes SHA256", len(sha256s))

            st.divider()

            # Tabela de Hashes (MD5 e SHA256)
            all_hashes = md5s + sha256s
            if all_hashes:
                st.write("### 🧩 Hashes de Arquivos (Malware)")
                hash_data = []
                with st.spinner("Consultando hashes na API do VirusTotal..."):
                    for h in all_hashes:
                        vt_resp = get_vt_data("files", h)
                        vt_summary = parse_vt_stats(vt_resp)
                        hash_data.append({
                            "Hash Original": h,
                            "Tipo": "SHA256" if len(h) == 64 else "MD5",
                            "Reputação VirusTotal (API)": vt_summary,
                            "Link Direto VT": f"https://www.virustotal.com/gui/file/{h}"
                        })
                st.dataframe(pd.DataFrame(hash_data), use_container_width=True)

            # Tabela de IPs
            if ips:
                st.write("### 🌐 Endereços IP (v4)")
                ip_data = []
                with st.spinner("Consultando IPs na API do VirusTotal..."):
                    for ip in ips:
                        vt_resp = get_vt_data("ip_addresses", ip)
                        vt_summary = parse_vt_stats(vt_resp)
                        ip_data.append({
                            "IP Neutralizado": defang(ip),
                            "Reputação VirusTotal (API)": vt_summary,
                            "Link VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
                            "Link AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}"
                        })
                st.dataframe(pd.DataFrame(ip_data), use_container_width=True)

            # Tabela de URLs
            if urls:
                st.write("### 🔗 URLs / Domínios")
                url_data = []
                with st.spinner("Analisando URLs..."):
                    for url in urls:
                        encoded_url = urllib.parse.quote(url, safe='')
                        url_data.append({
                            "URL Neutralizada": defang(url),
                            "Link VirusTotal": f"https://www.virustotal.com/gui/search/{encoded_url}"
                        })
                st.dataframe(pd.DataFrame(url_data), use_container_width=True)

            # E-mails encontrados
            if emails:
                st.write("### 📧 Endereços de E-mail")
                email_data = [{"E-mail Original": e, "E-mail Neutralizado": defang(e)} for e in emails]
                st.dataframe(pd.DataFrame(email_data), use_container_width=True)

            if not any([ips, urls, emails, md5s, sha256s]):
                st.info("Nenhum IOC comum (IP, URL, Hash, E-mail) foi identificado no texto fornecido.")

# =============================================================================
# RODAPÉ COM A MARCA CTRDEFENSE.BLOG
# =============================================================================
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; padding: 10px; color: #888888; font-size: 14px;">
        Powered by <strong><a href="https://ctrdefense.blog" target="_blank" style="color: #00a8e8; text-decoration: none;">CTRDEFENSE.BLOG</a></strong> | Cyber Security & SOC Tools
    </div>
    """,
    unsafe_allow_html=True
)
