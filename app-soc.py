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
    layout="wide"
)

# Estilização CSS personalizada
st.markdown("""
    <style>
        .main-header { font-size: 2.2rem; font-weight: 700; color: #00f2fe; margin-bottom: 0px; }
        .sub-header { font-size: 1rem; color: #94a3b8; margin-bottom: 20px; }
        .footer-text { text-align: center; padding: 15px; color: #64748b; font-size: 0.9rem; border-top: 1px solid #1e293b; margin-top: 40px; }
        .stTabs [data-baseweb="tab-list"] { gap: 6px; }
        .stTabs [data-baseweb="tab"] { background-color: #0f172a; border-radius: 6px; padding: 8px 14px; border: 1px solid #1e293b; color: #94a3b8; font-size: 0.9rem; }
        .stTabs [aria-selected="true"] { background-color: #1e293b !important; color: #00f2fe !important; border-color: #00f2fe !important; }
    </style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# HEADER & CARREGAMENTO DA API KEY
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ SOC Analyst Toolkit</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Suíte Unificada de Investigação de Incidentes, Threat Intel e Análise de Artefatos</div>', unsafe_allow_html=True)

VT_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")

status_col1, status_col2 = st.columns([3, 1])
with status_col1:
    st.caption("Central de Análise, Threat Hunting e Triagem Diária")
with status_col2:
    if VT_API_KEY and VT_API_KEY != "sua_chave_api_do_virustotal_aqui":
        st.success("🟢 API VirusTotal Conectada", icon="✅")
    else:
        st.warning("🟡 API VirusTotal Não Configurada", icon="⚠️")

st.divider()

# -----------------------------------------------------------------------------
# ENRIQUECIMENTO DE DADOS DA API VIRUSTOTAL V3
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
            return {"error": "Não encontrado na base VT"}
        elif response.status_code == 401:
            return {"error": "Chave API Inválida"}
        elif response.status_code == 429:
            return {"error": "Quota Excedida (Rate Limit)"}
        else:
            return {"error": f"Erro HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def parse_vt_details(vt_response):
    if "error" in vt_response:
        return {
            "verdict": f"⚠️ {vt_response['error']}",
            "score": "N/A",
            "detalhes": "N/D",
            "tags": []
        }
    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values())
        
        reputation = attrs.get("reputation", 0)
        tags = attrs.get("tags", [])[:3]

        if malicious > 0:
            verdict = f"🚨 Malicioso ({malicious}/{total})"
        elif suspicious > 0:
            verdict = f"⚠️ Suspeito ({suspicious}/{total})"
        else:
            verdict = f"✅ Limpo ({harmless}/{total})"

        detalhes_str = f"Malicioso: {malicious} | Suspeito: {suspicious} | Limpo: {harmless}"

        return {
            "verdict": verdict,
            "score": reputation,
            "detalhes": detalhes_str,
            "tags": ", ".join(tags) if tags else "Sem Tags"
        }
    except KeyError:
        return {"verdict": "Erro na estrutura", "score": "N/A", "detalhes": "N/D", "tags": "N/D"}

# -----------------------------------------------------------------------------
# NAVEGAÇÃO POR ABAS SUPERIORES
# -----------------------------------------------------------------------------
tab_iocs, tab_queries, tab_entropy, tab_email, tab_decoder, tab_ps_deobf, tab_network, tab_yara = st.tabs([
    "🔍 Extrator & VT",
    "🎯 SIEM/EDR Queries",
    "📊 Entropia",
    "📧 Analisador E-mail",
    "🔓 Decodificador",
    "⚔️ PS Deobfuscator",
    "🌐 IPs & CIDR",
    "📝 Gerador YARA"
])

# =============================================================================
# ABA 1: EXTRATOR, DEFANG E VIRUSTOTAL
# =============================================================================
with tab_iocs:
    st.header("🔍 Extrator de IOCs, Neutralizador (Defang) & Consultas VT")
    st.caption("Extraia artefatos, consulte a reputação detalhada no VirusTotal e abra as investigações em novas abas do navegador.")

    raw_text = st.text_area("Cole os logs, e-mails ou lista de hashes/IPs aqui:", height=150, placeholder="Ex: 192.168.1.1, https://malicious-site.com, hash sha256...")

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

            # Hashes
            all_hashes = md5s + sha256s
            if all_hashes:
                st.write("### 🧩 Hashes de Malware (MD5 / SHA256)")
                hash_data = []
                with st.spinner("Consultando dados detalhados da API VirusTotal..."):
                    for h in all_hashes:
                        vt_resp = get_vt_data("files", h)
                        vt_info = parse_vt_details(vt_resp)
                        hash_data.append({
                            "Hash Original": h,
                            "Tipo": "SHA256" if len(h) == 64 else "MD5",
                            "Veredito VT": vt_info["verdict"],
                            "Score VT": vt_info["score"],
                            "Distribuição de Detecções": vt_info["detalhes"],
                            "Tags Identificadas": vt_info["tags"],
                            "Link VirusTotal": f"https://www.virustotal.com/gui/file/{h}"
                        })

                df_hash = pd.DataFrame(hash_data)
                st.dataframe(
                    df_hash,
                    column_config={
                        "Link VirusTotal": st.column_config.LinkColumn(
                            "Link VirusTotal",
                            help="Clique para abrir o relatório completo em uma nova aba",
                            display_text="Abrir no VT ↗"
                        )
                    },
                    use_container_width=True,
                    hide_index=True
                )

            # IPs
            if ips:
                st.write("### 🌐 Endereços IP (v4)")
                ip_data = []
                with st.spinner("Consultando dados detalhados da API VirusTotal..."):
                    for ip in ips:
                        vt_resp = get_vt_data("ip_addresses", ip)
                        vt_info = parse_vt_details(vt_resp)
                        ip_data.append({
                            "IP Neutralizado": defang(ip),
                            "Veredito VT": vt_info["verdict"],
                            "Score VT": vt_info["score"],
                            "Distribuição de Detecções": vt_info["detalhes"],
                            "Link VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
                            "Link AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}"
                        })

                df_ip = pd.DataFrame(ip_data)
                st.dataframe(
                    df_ip,
                    column_config={
                        "Link VirusTotal": st.column_config.LinkColumn("Link VirusTotal", display_text="Abrir VT ↗"),
                        "Link AbuseIPDB": st.column_config.LinkColumn("Link AbuseIPDB", display_text="Abrir AbuseIPDB ↗")
                    },
                    use_container_width=True,
                    hide_index=True
                )

            # URLs
            if urls:
                st.write("### 🔗 URLs / Domínios")
                url_data = []
                for url in urls:
                    encoded_url = urllib.parse.quote(url, safe='')
                    url_data.append({
                        "URL Neutralizada": defang(url),
                        "Link VirusTotal": f"https://www.virustotal.com/gui/search/{encoded_url}"
                    })
                
                df_url = pd.DataFrame(url_data)
                st.dataframe(
                    df_url,
                    column_config={
                        "Link VirusTotal": st.column_config.LinkColumn("Link VirusTotal", display_text="Buscar no VT ↗")
                    },
                    use_container_width=True,
                    hide_index=True
                )

            # E-mails
            if emails:
                st.write("### 📧 E-mails")
                email_data = [{"E-mail Original": e, "E-mail Neutralizado": defang(e)} for e in emails]
                st.dataframe(pd.DataFrame(email_data), use_container_width=True, hide_index=True)

# =============================================================================
# ABA 2: OPÇÃO 1 - GERADOR DE CONSULTAS SIEM / EDR (KQL / EQL / FALCON)
# =============================================================================
with tab_queries:
    st.header("🎯 Threat Hunting Query Builder")
    st.caption("Gere automaticamente sintaxes válidas para busca de IOCs em plataformas SIEM (Microsoft Sentinel / Elastic) e EDR (CrowdStrike).")

    col_q1, col_q2 = st.columns([1, 2])
    with col_q1:
        ioc_type = st.selectbox("Tipo de Artefato (IOC):", ["Endereço IP", "Hash SHA256/MD5", "Nome do Arquivo / Processo", "Domínio / URL"])
        ioc_values = st.text_area("Insira os artefatos (um por linha):", height=120, placeholder="192.168.1.100\n10.0.0.5")
    
    with col_q2:
        siem_platform = st.radio("Plataforma Alvo:", ["Microsoft Sentinel (KQL)", "Elasticsearch (EQL / ESQL)", "CrowdStrike Falcon (Event Search)"], horizontal=True)

        if st.button("Gerar Queries de Hunting", type="primary"):
            items = [item.strip() for item in ioc_values.splitlines() if item.strip()]
            if not items:
                st.warning("Insira ao menos um indicador para gerar as consultas.")
            else:
                formatted_query = ""
                
                # --- SENTINEL (KQL) ---
                if siem_platform == "Microsoft Sentinel (KQL)":
                    if ioc_type == "Endereço IP":
                        ip_list = ", ".join([f"'{ip}'" for ip in items])
                        formatted_query = f"// Busca por conexões de rede de saída/entrada\nCommonSecurityLog\n| where DestinationIP in ({ip_list}) or SourceIP in ({ip_list})\n\n// Busca em eventos de endpoint (MDE)\nDeviceNetworkEvents\n| where RemoteIP in ({ip_list})"
                    elif ioc_type == "Hash SHA256/MD5":
                        hash_list = ", ".join([f"'{h}'" for h in items])
                        formatted_query = f"DeviceProcessEvents\n| where SHA256 in ({hash_list}) or MD5 in ({hash_list})"
                    elif ioc_type == "Nome do Arquivo / Processo":
                        proc_list = ", ".join([f"'{p}'" for p in items])
                        formatted_query = f"DeviceProcessEvents\n| where FileName in~ ({proc_list}) or ProcessVersionInfoOriginalFileName in~ ({proc_list})"
                    elif ioc_type == "Domínio / URL":
                        dom_list = ", ".join([f"'{d}'" for d in items])
                        formatted_query = f"DeviceEvents\n| where ActionType == 'DnsQueryInitiated'\n| extend DNSName = tostring(AdditionalFields.Name)\n| where DNSName in~ ({dom_list})"

                # --- ELASTICSEARCH (EQL) ---
                elif siem_platform == "Elasticsearch (EQL / ESQL)":
                    if ioc_type == "Endereço IP":
                        ip_list = ", ".join([f'"{ip}"' for ip in items])
                        formatted_query = f"sequence by host.id\n [ network where destination.ip in ({ip_list}) or source.ip in ({ip_list}) ]"
                    elif ioc_type == "Hash SHA256/MD5":
                        hash_list = ", ".join([f'"{h}"' for h in items])
                        formatted_query = f"process where process.hash.sha256 in ({hash_list}) or process.hash.md5 in ({hash_list})"
                    elif ioc_type == "Nome do Arquivo / Processo":
                        proc_list = ", ".join([f'"{p}"' for p in items])
                        formatted_query = f"process where process.name in ({proc_list}) or process.pe.original_file_name in ({proc_list})"
                    elif ioc_type == "Domínio / URL":
                        dom_list = ", ".join([f'"{d}"' for d in items])
                        formatted_query = f"network where dns.question.name in ({dom_list})"

                # --- CROWDSTRIKE FALCON ---
                elif siem_platform == "CrowdStrike Falcon (Event Search)":
                    if ioc_type == "Endereço IP":
                        ip_or = " OR ".join([f"RemoteAddressIP4=\"{ip}\"" for ip in items])
                        formatted_query = f"event_simpleName=NetworkConnectIP4 ({ip_or})"
                    elif ioc_type == "Hash SHA256/MD5":
                        hash_or = " OR ".join([f"SHA256HashData=\"{h}\" OR MD5HashData=\"{h}\"" for h in items])
                        formatted_query = f"event_simpleName=ProcessRollup2 ({hash_or})"
                    elif ioc_type == "Nome do Arquivo / Processo":
                        proc_or = " OR ".join([f"FileName=\"{p}\"" for p in items])
                        formatted_query = f"event_simpleName=ProcessRollup2 ({proc_or})"
                    elif ioc_type == "Domínio / URL":
                        dom_or = " OR ".join([f"DomainName=\"{d}\"" for d in items])
                        formatted_query = f"event_simpleName=DnsRequest ({dom_or})"

                st.subheader("Sintaxe Gerada:")
                st.code(formatted_query, language="sql")

# =============================================================================
# ABA 3: OPÇÃO 2 - CALCULADOR DE ENTROPIA DE ARQUIVOS E PAYLOADS
# =============================================================================
with tab_entropy:
    st.header("📊 Calculador de Entropia de Shannon")
    st.caption("A entropia mede o grau de aleatoriedade dos bytes. Valores elevados (> 7.2) indicam forte probabilidade de empacotamento (packer), obfuscação ou criptografia por ransomware.")

    def calculate_shannon_entropy(data_bytes):
        if not data_bytes:
            return 0.0
        entropy = 0.0
        byte_counts = [0] * 256
        for b in data_bytes:
            byte_counts[b] += 1
        total_bytes = len(data_bytes)
        for count in byte_counts:
            if count == 0:
                continue
            p = count / total_bytes
            entropy -= p * math.log2(p)
        return entropy

    st.subheader("Selecione o Método de Entrada:")
    input_type = st.radio("Entrada via:", ["Texto / Base64", "Upload de Arquivo (PE, DLL, Script)"], horizontal=True)

    bytes_to_analyze = b""
    filename = ""

    if input_type == "Texto / Base64":
        raw_string = st.text_area("Cole o texto, payload ou string Base64 aqui:", height=150, placeholder="Ex: TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...")
        if raw_string.strip():
            # Tenta decodificar caso seja Base64 puro
            try:
                bytes_to_analyze = base64.b64decode(raw_string.strip())
            except Exception:
                bytes_to_analyze = raw_string.encode('utf-8')
            filename = "String / Payload Manual"
    else:
        uploaded_file = st.file_uploader("Envie um arquivo suspeito (Máx: 20MB):", type=None)
        if uploaded_file is not None:
            bytes_to_analyze = uploaded_file.read()
            filename = uploaded_file.name

    if bytes_to_analyze:
        entropy_val = calculate_shannon_entropy(bytes_to_analyze)
        
        st.divider()
        st.subheader("Análise de Entropia do Artefato")
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Tamanho Analisado", f"{len(bytes_to_analyze)} Bytes")
        m2.metric("Score de Entropia", f"{entropy_val:.4f} / 8.0")

        # Avaliação de Risco da Entropia
        if entropy_val < 5.0:
            status = "🟢 Baixa Entropia (Texto Simples / Não Empacotado)"
            desc = "O conteúdo possui distribuição de bytes previsível. Típico de código fonte limpo ou arquivos de texto puro."
            color_type = st.success
        elif 5.0 <= entropy_val <= 7.1:
            status = "🟡 Entropia Média (Binário Padrão / Executável Compilado)"
            desc = "Faixa normal para arquivos PE compilados (.exe, .dll) sem proteções avançadas de packers."
            color_type = st.info
        else:
            status = "🚨 Altíssima Entropia (Packed / Crypt / Obfuscated)"
            desc = "Indício crítico de uso de Packers (UPX, Themida), Criptografia de Ransomware ou Obfuscação de Payload."
            color_type = st.error

        color_type(f"**Veredito:** {status}")
        st.caption(desc)

# =============================================================================
# ABA 4: ANALISADOR DE E-MAIL
# =============================================================================
with tab_email:
    st.header("📧 Analisador de Cabeçalhos de E-mail (Phishing)")
    st.caption("Verifique mecanicamente os registros SPF, DKIM e DMARC e trace a rota dos servidores por onde a mensagem transitou.")

    raw_header = st.text_area("Cole o cabeçalho bruto (Raw Header) do e-mail:", height=180)

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
                st.dataframe(df_hops, use_container_width=True, hide_index=True)

# =============================================================================
# ABA 5: DECODIFICADOR GENÉRICO
# =============================================================================
with tab_decoder:
    st.header("🔓 Decodificador & Desobfuscador de Payload")
    st.caption("Decodifique rapidamente strings em Base64, PowerShell `-EncodedCommand` e URL Encoding.")

    encoded_input = st.text_area("Insira a string obfuscada aqui:", height=150)

    if st.button("Decodificar Artefato", type="primary"):
        if not encoded_input.strip():
            st.warning("Forneça uma string para decodificar.")
        else:
            st.subheader("Resultados Obtidos")
            
            url_decoded = urllib.parse.unquote(encoded_input)
            st.text_input("1. URL Decoded:", value=url_decoded)

            try:
                b64_bytes = base64.b64decode(encoded_input.strip())
                try:
                    b64_utf8 = b64_bytes.decode('utf-8')
                    st.text_area("2. Base64 (UTF-8 / Texto Simples):", value=b64_utf8, height=100)
                except UnicodeDecodeError:
                    pass

                try:
                    b64_utf16 = b64_bytes.decode('utf-16')
                    st.text_area("3. Base64 (UTF-16 LE / Comandos PowerShell):", value=b64_utf16, height=100)
                except UnicodeDecodeError:
                    pass
            except Exception:
                st.error("A string informada não é um Base64 válido ou possui erros de padding.")

# =============================================================================
# ABA 6: POWERSHELL DEOBFUSCATOR
# =============================================================================
with tab_ps_deobf:
    st.header("⚔️ PowerShell & Command Line Deobfuscator")
    st.caption("Remova acentos graves (`), concatenações de strings e identifique automaticamente chamadas de rede ocultas em linhas de comando do Windows.")

    ps_input = st.text_area("Cole a linha de comando suspeita / Script obfuscado:", height=150, 
                            placeholder="Exemplo: p`o`w`e`r`s`h`e`l`l -e`n`c [Base64] OU 'ht'+'tp://'+'malware.com/payload.exe'")

    if st.button("Desobfuscar Script", type="primary"):
        if not ps_input.strip():
            st.warning("Insira uma linha de comando para desobfuscar.")
        else:
            cleaned = ps_input

            cleaned = cleaned.replace("`", "")
            cleaned = cleaned.replace("^", "")
            cleaned = re.sub(r"['\"](?:\s*\+\s*)['\"]", "", cleaned)

            b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', cleaned)

            st.subheader("1. Código Sanitizado (Limpas Técnicas de Evasão)")
            st.code(cleaned, language="powershell")

            if b64_matches:
                st.subheader("2. Payloads Base64 Encontrados e Decodificados")
                for idx, match in enumerate(b64_matches, 1):
                    try:
                        decoded_bytes = base64.b64decode(match)
                        try:
                            decoded_str = decoded_bytes.decode('utf-16le')
                        except UnicodeDecodeError:
                            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        
                        st.markdown(f"**Payload Encontrado #{idx}:**")
                        st.code(decoded_str, language="powershell")
                    except Exception:
                        pass

            urls_found = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', cleaned)
            if urls_found:
                st.subheader("3. 🎯 URLs Maliciosas Extraídas do Script")
                for u in set(urls_found):
                    st.error(f"URL de Download Identificada: `{u}`")

# =============================================================================
# ABA 7: IPS & SUB-REDES
# =============================================================================
with tab_network:
    st.header("🌐 Classificador de IPs & Calculadora CIDR")
    st.caption("Identifique se um IP pertence à rede privada interna (RFC 1918) ou à internet pública e calcule sub-redes.")

    subtab1, subtab2 = st.tabs(["Análise de IPs em Lote", "Calculadora CIDR"])

    with subtab1:
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
                    results.append({"IP": ip_str, "Classificação": "❌ Formato Inválido", "Versão": "N/A"})
            st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)

    with subtab2:
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

# =============================================================================
# ABA 8: GERADOR DE REGRAS YARA
# =============================================================================
with tab_yara:
    st.header("📝 Gerador Automático de Regras YARA")
    st.caption("Crie rapidamente regras YARA sintaticamente válidas para detecção em EDRs, SIEMs ou análise de malware.")

    col_meta1, col_meta2 = st.columns(2)
    with col_meta1:
        rule_name = st.text_input("Nome da Regra (Rule Name):", value="APT_Suspicious_Script_Pattern").replace(" ", "_")
        author = st.text_input("Autor / Time de SOC:", value="CTRDEFENSE Analyst")
    with col_meta2:
        description = st.text_input("Descrição:", value="Detecta padrões de comandos obfuscados em arquivos")
        severity = st.selectbox("Severidade:", ["Baixa", "Média", "Alta", "Crítica"])

    st.subheader("Definição de Strings & Padrões (IOCs)")
    str1 = st.text_input("String 1 ($str1):", value="powershell.exe -EncodedCommand")
    str2 = st.text_input("String 2 ($str2):", value="Invoke-Expression")
    str3 = st.text_input("String 3 ($str3):", value="http://malicious-domain.com")

    condition_type = st.selectbox(
        "Condição de Disparo (Condition):",
        ["all of them", "any of them", "2 of them", "uint16(0) == 0x5A4D and any of them (PE Files)"]
    )

    yara_code = f"""rule {rule_name} {{
    meta:
        description = "{description}"
        author = "{author}"
        severity = "{severity}"
        reference = "CTRDEFENSE.BLOG"

    strings:
        $str1 = "{str1}" ascii wide
        $str2 = "{str2}" ascii wide
        $str3 = "{str3}" ascii wide

    condition:
        {condition_type}
}}"""

    st.subheader("Regra YARA Gerada:")
    st.code(yara_code, language="yara")

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
