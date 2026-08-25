import re
import base64
import urllib.parse
import ipaddress
import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# CONFIGURAÇÃO DA PÁGINA & TEMA SOC
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Analyst Toolkit | CTRDEFENSE.BLOG",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilização CSS personalizada para dar visual profissional
st.markdown("""
    <style>
        .main-header {
            font-size: 2.2rem;
            font-weight: 700;
            color: #00f2fe;
            margin-bottom: 0px;
        }
        .sub-header {
            font-size: 1rem;
            color: #94a3b8;
            margin-bottom: 25px;
        }
        .footer-text {
            text-align: center;
            padding: 15px;
            color: #64748b;
            font-size: 0.9rem;
            border-top: 1px solid #1e293b;
            margin-top: 40px;
        }
        .stMetric {
            background-color: #0f172a;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #1e293b;
        }
    </style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# HEADER PRINCIPAL
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ SOC Analyst Toolkit</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Suíte Unificada de Investigação de Incidentes, Threat Intel e Análise de Artefatos</div>', unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# GERENCIAMENTO DE SECRETS DA API VIRUSTOTAL
# -----------------------------------------------------------------------------
VT_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")

def get_vt_data(endpoint, item_id):
    """Consulta a API v3 do VirusTotal."""
    if not VT_API_KEY:
        return {"error": "API Key não configurada nos Secrets"}

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
            return {"error": "Não encontrado na base do VirusTotal"}
        elif response.status_code == 401:
            return {"error": "Chave de API Inválida"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def parse_vt_stats(vt_response):
    """Formata o resultado da análise de reputação."""
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
# MENU LATERAL INTERATIVO (SIDEBAR)
# -----------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=60)
    st.title("Painel de Controle")
    
    selected_tool = st.selectbox(
        "Selecione o Módulo de Trabalho:",
        [
            "🔍 Extrator, Defang e VirusTotal (IOCs)",
            "📧 Analisador de Cabeçalho de E-mail",
            "🔓 Decodificador & Desobfuscador",
            "🌐 Analisador de IPs & Sub-redes (RFC 1918)"
        ]
    )
    
    st.divider()
    
    # Status da API Key
    st.subheader("Status das Integrações")
    if VT_API_KEY:
        st.success("🟢 API VirusTotal: Conectada")
    else:
        st.warning("🟡 API VirusTotal: Desconectada")
        st.caption("Adicione `VIRUSTOTAL_API_KEY` nos secrets para ativar consultas em tempo real.")

    st.divider()
    st.caption("Powered by **CTRDEFENSE.BLOG**")


# =============================================================================
# MÓDULO 1: EXTRATOR, DEFANG E VIRUSTOTAL
# =============================================================================
if selected_tool == "🔍 Extrator, Defang e VirusTotal (IOCs)":
    st.header("🔍 Extrator, Neutralizador (Defang) & Enriquecimento VT")
    st.caption("Extraia automaticamente artefatos de logs/relatórios, aplique defang para neutralizar links e consulte o VirusTotal.")

    raw_text = st.text_area("Cole os logs, e-mails ou lista de hashes/IPs aqui:", height=180, placeholder="Ex: 192.168.1.1, https://malicious-site.com, hash sha256...")

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

    if st.button("Executar Análise de IOCs", type="primary"):
        if not raw_text.strip():
            st.warning("Por favor, cole um texto antes de executar.")
        else:
            ips, urls, emails, md5s, sha256s = extract_iocs(raw_text)

            st.subheader("📊 Indicadores Identificados")
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("IPs (v4)", len(ips))
            c2.metric("URLs", len(urls))
            c3.metric("E-mails", len(emails))
            c4.metric("Hashes MD5", len(md5s))
            c5.metric("Hashes SHA256", len(sha256s))

            st.divider()

            # Tabela de Hashes
            all_hashes = md5s + sha256s
            if all_hashes:
                st.write("### 🧩 Hashes de Malware (MD5 / SHA256)")
                hash_data = []
                with st.spinner("Consultando reputação na API do VirusTotal..."):
                    for h in all_hashes:
                        vt_resp = get_vt_data("files", h)
                        hash_data.append({
                            "Hash Original": h,
                            "Tipo": "SHA256" if len(h) == 64 else "MD5",
                            "Reputação VirusTotal": parse_vt_stats(vt_resp),
                            "Link VirusTotal": f"https://www.virustotal.com/gui/file/{h}"
                        })
                st.dataframe(pd.DataFrame(hash_data), use_container_width=True)

            # Tabela de IPs
            if ips:
                st.write("### 🌐 Endereços IP (v4)")
                ip_data = []
                with st.spinner("Consultando IPs na API do VirusTotal..."):
                    for ip in ips:
                        vt_resp = get_vt_data("ip_addresses", ip)
                        ip_data.append({
                            "IP Neutralizado (Defanged)": defang(ip),
                            "Reputação VirusTotal": parse_vt_stats(vt_resp),
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
                        "URL Neutralizada": defang(url),
                        "Link VirusTotal": f"https://www.virustotal.com/gui/search/{encoded_url}"
                    })
                st.dataframe(pd.DataFrame(url_data), use_container_width=True)

            # E-mails
            if emails:
                st.write("### 📧 E-mails")
                email_data = [{"E-mail Original": e, "E-mail Neutralizado": defang(e)} for e in emails]
                st.dataframe(pd.DataFrame(email_data), use_container_width=True)

            if not any([ips, urls, emails, md5s, sha256s]):
                st.info("Nenhum IOC padrão foi encontrado no texto.")


# =============================================================================
# MÓDULO 2: ANALISADOR DE CABEÇALHO DE E-MAIL
# =============================================================================
elif selected_tool == "📧 Analisador de Cabeçalho de E-mail":
    st.header("📧 Analisador de Cabeçalhos de E-mail (Phishing)")
    st.caption("Verifique mecanicamente os registros SPF, DKIM e DMARC e trace a rota dos servidores.")

    raw_header = st.text_area("Cole o cabeçalho bruto (Raw Header) do e-mail:", height=200)

    def parse_authentication(header_text):
        auth_results = {"SPF": "NÃO ENCONTRADO", "DKIM": "NÃO ENCONTRADO", "DMARC": "NÃO ENCONTRADO"}
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
            hops.append({"Salto (#)": i, "Servidor / IP Roteado": clean_line})
        return pd.DataFrame(hops)

    if st.button("Analisar Cabeçalho", type="primary"):
        if not raw_header.strip():
            st.warning("Insira um cabeçalho válido antes de prosseguir.")
        else:
            st.subheader("1. Mecanismos de Autenticação")
            auth_data = parse_authentication(raw_header)
            c1, c2, c3 = st.columns(3)

            with c1:
                st.metric("SPF Status", auth_data["SPF"], 
                          delta="PASS" if auth_data["SPF"] == "PASS" else "-ALERTA",
                          delta_color="normal" if auth_data["SPF"] == "PASS" else "inverse")
            with c2:
                st.metric("DKIM Status", auth_data["DKIM"], 
                          delta="PASS" if auth_data["DKIM"] == "PASS" else "-ALERTA",
                          delta_color="normal" if auth_data["DKIM"] == "PASS" else "inverse")
            with c3:
                st.metric("DMARC Status", auth_data["DMARC"], 
                          delta="PASS" if auth_data["DMARC"] == "PASS" else "-ALERTA",
                          delta_color="normal" if auth_data["DMARC"] == "PASS" else "inverse")

            st.divider()
            st.subheader("2. Saltos de Rede (Network Hops)")
            df_hops = parse_hops(raw_header)
            if not df_hops.empty:
                st.dataframe(df_hops, use_container_width=True)
            else:
                st.info("Nenhum salto 'Received:' foi localizado no cabeçalho.")


# =============================================================================
# MÓDULO 3: DECODIFICADOR & DESOBFUSCADOR
# =============================================================================
elif selected_tool == "🔓 Decodificador & Desobfuscador":
    st.header("🔓 Decodificador & Desobfuscador de Payload")
    st.caption("Decodifique rapidamente strings em Base64, PowerShell `-EncodedCommand` e URL Encoding.")

    encoded_input = st.text_area("Insira a string obfuscada aqui:", height=150)

    if st.button("Decodificar Artefato", type="primary"):
        if not encoded_input.strip():
            st.warning("Forneça uma string para decodificar.")
        else:
            st.subheader("Resultados Obtidos")
            
            # URL Decode
            url_decoded = urllib.parse.unquote(encoded_input)
            st.text_input("1. URL Decoded:", value=url_decoded)

            # Base64 Decode
            try:
                b64_bytes = base64.b64decode(encoded_input.strip())
                
                # Tenta UTF-8
                try:
                    b64_utf8 = b64_bytes.decode('utf-8')
                    st.text_area("2. Base64 (UTF-8 / Texto Simples):", value=b64_utf8, height=120)
                except UnicodeDecodeError:
                    st.info("O conteúdo Base64 não aparenta ser UTF-8 legível.")

                # Tenta UTF-16 (PowerShell -Enc)
                try:
                    b64_utf16 = b64_bytes.decode('utf-16')
                    st.text_area("3. Base64 (UTF-16 LE / Comandos PowerShell):", value=b64_utf16, height=120)
                except UnicodeDecodeError:
                    pass

            except Exception:
                st.error("A string informada não é um Base64 válido ou possui erros de padding.")


# =============================================================================
# MÓDULO 4: ANALISADOR DE IP E SUB-REDES
# =============================================================================
elif selected_tool == "🌐 Analisador de IPs & Sub-redes (RFC 1918)":
    st.header("🌐 Classificador de IPs & Calculadora CIDR")
    st.caption("Identifique se um IP pertence à rede privada interna ou à internet pública e calcule sub-redes.")

    tab1, tab2 = st.tabs(["Análise em Lote de IPs", "Calculadora de Bloco CIDR"])

    with tab1:
        raw_ips = st.text_area("Cole uma lista de IPs (um por linha):", height=150, placeholder="10.0.0.1\n8.8.8.8\n172.16.5.10")
        if st.button("Classificar Lista de IPs"):
            ip_lines = [line.strip() for line in raw_ips.splitlines() if line.strip()]
            results = []
            for ip_str in ip_lines:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    tipo = "🔒 Privado (Interno RFC 1918)" if ip_obj.is_private else "🌍 Público (Externo / Internet)"
                    if ip_obj.is_loopback: tipo = "🔄 Loopback"
                    results.append({"IP": ip_str, "Classificação": tipo, "Versão": f"IPv{ip_obj.version}"})
                except ValueError:
                    results.append({"IP": ip_str, "Classificação": "❌ Formato de IP Inválido", "Versão": "N/A"})
            st.dataframe(pd.DataFrame(results), use_container_width=True)

    with tab2:
        cidr_input = st.text_input("Insira o bloco CIDR (ex: 10.0.0.0/24):", value="192.168.1.0/24")
        if cidr_input:
            try:
                net = ipaddress.ip_network(cidr_input, strict=False)
                c1, c2, c3 = st.columns(3)
                c1.metric("Endereço da Rede", str(net.network_address))
                c2.metric("Endereço Broadcast", str(net.broadcast_address))
                c3.metric("Total de Hosts Válidos", net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses)
                
                st.info(f"**Máscara de Rede:** `{net.netmask}` | **Primeiro Host Válido:** `{net.network_address + 1}` | **Último Host Válido:** `{net.broadcast_address - 1}`")
            except ValueError:
                st.error("Formato CIDR inválido. Exemplo correto: 10.0.0.0/22")

# -----------------------------------------------------------------------------
# RODAPÉ INSTITUCIONAL
# -----------------------------------------------------------------------------
st.markdown(
    """
    <div class="footer-text">
        Powered by <strong><a href="https://ctrdefense.blog" target="_blank" style="color: #00f2fe; text-decoration: none;">CTRDEFENSE.BLOG</a></strong> | Cyber Security & SOC Tools
    </div>
    """,
    unsafe_allow_html=True
)
