import re
import urllib.parse
import pandas as pd
import streamlit as st

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Analyst Toolkit",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Analyst Toolkit - by Cyber Threat Research Defense")
st.markdown("Painel unificado de ferramentas para análise de incidentes e operações de segurança.")

# -----------------------------------------------------------------------------
# MENU LATERAL DE NAVEGAÇÃO
# -----------------------------------------------------------------------------
st.sidebar.header("⚙️ Navegação")
menu_option = st.sidebar.radio(
    "Escolha a Ferramenta:",
    [
        "📧 Analisador de Cabeçalho de E-mail",
        "🔍 Extrator e Defang de IOCs (Threat Intel)"
    ]
)

st.sidebar.divider()

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
# FERRAMENTA 2: EXTRATOR E NEUTRALIZADOR DE IOCS (DEFANGER)
# =============================================================================
elif menu_option == "🔍 Extrator e Defang de IOCs (Threat Intel)":
    st.header("🔍 Extrator e Neutralizador de IOCs (Defanger)")
    st.caption("Cole um log, relatório ou e-mail bruto para extrair IPs, URLs e Hashes neutralizados para uso em tickets do SOC.")

    raw_text = st.text_area("Cole o texto bruto (logs, alertas, relatórios) aqui:", height=200)

    def defang(value):
        """Substitui pontos e protocolos para evitar cliques acidentais."""
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

    def extract_iocs(text):
        # Expressoes Regulares para IOCs comuns
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

    if st.button("Extrair e Neutralizar IOCs", type="primary"):
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

            # Tabela de IPs
            if ips:
                st.write("### 🌐 Endereços IP (v4)")
                ip_data = []
                for ip in ips:
                    ip_data.append({
                        "IP Original": ip,
                        "IP Neutralizado (Defanged)": defang(ip),
                        "Link VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
                        "Link AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}"
                    })
                st.dataframe(pd.DataFrame(ip_data), use_container_width=True)

            # Tabela de URLs
            if urls:
                st.write("### 🔗 URLs / Domínios")
                url_data = []
                for url in urls:
                    encoded_url = urllib.parse.quote(url, safe='')
                    url_data.append({
                        "URL Neutralizada (Defanged)": defang(url),
                        "Link VirusTotal": f"https://www.virustotal.com/gui/search/{encoded_url}"
                    })
                st.dataframe(pd.DataFrame(url_data), use_container_width=True)

            # Tabela de Hashes (MD5 e SHA256)
            if md5s or sha256s:
                st.write("### 🧩 Hashes de Arquivo (Malware)")
                hash_data = []
                for h in md5s:
                    hash_data.append({"Tipo": "MD5", "Hash Original": h, "Link VirusTotal": f"https://www.virustotal.com/gui/file/{h}"})
                for h in sha256s:
                    hash_data.append({"Tipo": "SHA256", "Hash Original": h, "Link VirusTotal": f"https://www.virustotal.com/gui/file/{h}"})
                st.dataframe(pd.DataFrame(hash_data), use_container_width=True)

            # E-mails encontrados
            if emails:
                st.write("### 📧 Endereços de E-mail")
                email_data = [{"E-mail Original": e, "E-mail Neutralizado": defang(e)} for e in emails]
                st.dataframe(pd.DataFrame(email_data), use_container_width=True)

            if not any([ips, urls, emails, md5s, sha256s]):
                st.info("Nenhum IOC comum (IP, URL, Hash, E-mail) foi identificado no texto fornecido.")
