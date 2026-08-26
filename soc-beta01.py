import re
import math
import base64
import urllib.parse
import ipaddress
import pandas as pd
import requests
import streamlit as st

# -----------------------------------------------------------------------------
# 1. CONFIGURAÇÃO DA PÁGINA
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Platform Architecture for Threat Intelligence V1.0 Beta",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# 2. DESIGN SYSTEM: CSS CYBERPUNK / GLASSMORPHISM & JAVASCRIPT
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
# 3. GERENCIAMENTO SEGURO DA API KEY (INTERFACE + SECRETS.TOML)
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔑 Credenciais Threat Intel")
    
    # Leitura com fallback do .streamlit/secrets.toml
    default_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")

    # Campo de senha para inserção e ocultação visual na interface
    user_vt_key = st.text_input(
        "VirusTotal API Key:",
        value=st.session_state.get("vt_key_input", default_key),
        type="password",
        help="Insira sua chave API do VirusTotal v3.",
        key="vt_key_input"
    )

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("💾 Salvar", use_container_width=True):
            st.session_state["active_vt_key"] = user_vt_key
            st.success("Salva!")
            st.rerun()

    with col_btn2:
        if st.button("🗑️ Limpar", use_container_width=True):
            st.session_state["vt_key_input"] = ""
            st.session_state["active_vt_key"] = ""
            st.warning("Removida!")
            st.rerun()

    st.divider()

# Prioridade: Session State Manual > Campo Input > secrets.toml
VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", default_key))

# -----------------------------------------------------------------------------
# 4. HEADER DA APLICAÇÃO & STATUS DA API
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Platform Architecture for Threat Intelligence V1.0 Beta</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Detection Engineering, Incident Response & Dynamic Threat Mapping</div>', unsafe_allow_html=True)

status_col1, status_col2 = st.columns([3, 1])
with status_col1:
    st.caption("Central de Análise, Threat Hunting e Triagem Diária")
with status_col2:
    if VT_API_KEY and VT_API_KEY.strip() != "" and VT_API_KEY != "sua_chave_api_do_virustotal_aqui":
        st.success("🟢 VirusTotal Conectado", icon="✅")
    else:
        st.warning("🟡 API Key Ausente", icon="⚠️")

# -----------------------------------------------------------------------------
# 5. QUICK-ACCESS THREAT INTEL HUB
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
# 6. MÓDULO VIRUSTOTAL API V3
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
        elif response.status_code == 401:
            return {"error": "Chave API Inválida"}
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

if "last_analyzed_text" not in st.session_state:
    st.session_state["last_analyzed_text"] = ""

# -----------------------------------------------------------------------------
# 7. NAVEGAÇÃO POR ABAS OPERACIONAIS
# -----------------------------------------------------------------------------
tab_iocs, tab_mitre, tab_queries, tab_entropy, tab_email, tab_decoder, tab_ps_deobf, tab_network = st.tabs([
    "🔍 Extrator & VT",
    "🥷 MITRE ATT&CK & APTs",
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
# ABA 2: MAPEADOR DINÂMICO MITRE ATT&CK E MAPEAMENTO DE APTS
# =============================================================================
with tab_mitre:
    st.header("🥷 Mapeamento Dinâmico de TTPs & Grupos Adversários (APTs)")
    st.caption("Identificação automática de Táticas e Técnicas com vinculação direta a perfis de APTs conhecidas.")

    target_text = st.session_state.get("last_analyzed_text", "")

    def map_mitre_ttps_and_apts(text):
        results = []
        patterns = [
            {
                "pattern": r'powershell|pwsh|-enc|-encodedcommand',
                "tactic": 'Execution',
                "tech_name": 'Command and Scripting Interpreter: PowerShell',
                "tech_id": 'T1059.001',
                "desc": 'Uso do PowerShell para execução de scripts arbitrários e automação.',
                "apts": [
                    {"name": "APT29 (Cozy Bear)", "url": "https://attack.mitre.org/groups/G0016/"},
                    {"name": "APT28 (Fancy Bear)", "url": "https://attack.mitre.org/groups/G0007/"},
                    {"name": "FIN7", "url": "https://attack.mitre.org/groups/G0046/"},
                    {"name": "Lazarus Group", "url": "https://attack.mitre.org/groups/G0032/"}
                ]
            },
            {
                "pattern": r'cmd\.exe|/c|/k',
                "tactic": 'Execution',
                "tech_name": 'Command and Scripting Interpreter: Windows Command Shell',
                "tech_id": 'T1059.003',
                "desc": 'Execução de comandos nativos via Windows Command Shell.',
                "apts": [
                    {"name": "APT41", "url": "https://attack.mitre.org/groups/G0096/"},
                    {"name": "MuddyWater", "url": "https://attack.mitre.org/groups/G0069/"},
                    {"name": "OilRig", "url": "https://attack.mitre.org/groups/G0049/"}
                ]
            },
            {
                "pattern": r'reg add|HKLM|HKCU|CurrentVersion\\Run',
                "tactic": 'Persistence',
                "tech_name": 'Boot or Logon Autostart Execution: Registry Run Keys',
                "tech_id": 'T1547.001',
                "desc": 'Modificação de chaves de registro do Windows para garantir persistência.',
                "apts": [
                    {"name": "APT33", "url": "https://attack.mitre.org/groups/G0064/"},
                    {"name": "Wizard Spider", "url": "https://attack.mitre.org/groups/G0102/"},
                    {"name": "Sandworm Team", "url": "https://attack.mitre.org/groups/G0034/"}
                ]
            },
            {
                "pattern": r'lsass|mimikatz|sekurlsa|sekurlsa::logonpasswords',
                "tactic": 'Credential Access',
                "tech_name": 'OS Credential Dumping: LSASS Memory',
                "tech_id": 'T1003.001',
                "desc": 'Extração de credenciais e hashes em memória através do processo LSASS.',
                "apts": [
                    {"name": "APT32 (OceanLotus)", "url": "https://attack.mitre.org/groups/G0050/"},
                    {"name": "Threat Group-3390", "url": "https://attack.mitre.org/groups/G0027/"},
                    {"name": "Lazarus Group", "url": "https://attack.mitre.org/groups/G0032/"}
                ]
            },
            {
                "pattern": r'bitsadmin|certutil|curl|wget',
                "tactic": 'Defense Evasion',
                "tech_name": 'Ingress Tool Transfer',
                "tech_id": 'T1105',
                "desc": 'Transferência de ferramentas ou payloads usando utilitários legítimos (LOLBins).',
                "apts": [
                    {"name": "APT38", "url": "https://attack.mitre.org/groups/G0082/"},
                    {"name": "Kimsuky", "url": "https://attack.mitre.org/groups/G0094/"},
                    {"name": "Turla", "url": "https://attack.mitre.org/groups/G0010/"}
                ]
            },
            {
                "pattern": r'schtasks|taskengine',
                "tactic": 'Persistence',
                "tech_name": 'Scheduled Task/Job: Scheduled Task',
                "tech_id": 'T1053.005',
                "desc": 'Agendamento de tarefas para execução persistente de código.',
                "apts": [
                    {"name": "Dragonfly", "url": "https://attack.mitre.org/groups/G0035/"},
                    {"name": "FIN6", "url": "https://attack.mitre.org/groups/G0037/"}
                ]
            },
            {
                "pattern": r'vssadmin|delete shadows|wmic shadowcopy delete',
                "tactic": 'Impact',
                "tech_name": 'Inhibit System Recovery',
                "tech_id": 'T1490',
                "desc": 'Destruição de Shadow Copies para impedir restauração do sistema (padrão Ransomware).',
                "apts": [
                    {"name": "INDIGO ZER0 / BlackCat", "url": "https://attack.mitre.org/groups/G1018/"},
                    {"name": "Wizard Spider (Ryuk/Conti)", "url": "https://attack.mitre.org/groups/G0102/"}
                ]
            },
            {
                "pattern": r'https?://[^\s<>"]+',
                "tactic": 'Command and Control',
                "tech_name": 'Application Layer Protocol: Web Protocols',
                "tech_id": 'T1071.001',
                "desc": 'Uso de tráfego HTTP/HTTPS para comunicação C2 com infraestrutura externa.',
                "apts": [
                    {"name": "APT40", "url": "https://attack.mitre.org/groups/G0065/"},
                    {"name": "APT29", "url": "https://attack.mitre.org/groups/G0016/"}
                ]
            }
        ]

        for item in patterns:
            if re.search(item["pattern"], text, re.IGNORECASE):
                mitre_link = f"https://attack.mitre.org/techniques/{item['tech_id'].replace('.', '/')}/"
                apt_links = ", ".join([f"[{apt['name']}]({apt['url']})" for apt in item["apts"]])
                
                results.append({
                    "Tática": item["tactic"],
                    "ID Técnica": item["tech_id"],
                    "Técnica MITRE": item["tech_name"],
                    "Grupos Adversários (APTs)": apt_links,
                    "Descrição do Comportamento": item["desc"],
                    "Link MITRE": mitre_link
                })
        return results

    if not target_text.strip():
        st.info("💡 Insira um log na aba **'🔍 Extrator & VT'** e clique em 'Executar Triagem' para carregar a matriz e as APTs nesta aba.")
    else:
        mitre_data = map_mitre_ttps_and_apts(target_text)
        if mitre_data:
            st.success(f"🎯 Mapeamento concluído! Identificadas **{len(mitre_data)} TTPs** no payload analisado.")
            df_mitre = pd.DataFrame(mitre_data)
            
            st.dataframe(
                df_mitre,
                column_config={
                    "Link MITRE": st.column_config.LinkColumn("Técnica MITRE ↗", display_text="Ver no MITRE ↗"),
                    "Grupos Adversários (APTs)": st.column_config.TextColumn(
                        "Grupos Adversários (APTs Clicáveis)",
                        help="Grupos hackers associados a esta técnica."
                    )
                },
                use_container_width=True,
                hide_index=True
            )
            
            st.markdown("---")
            st.subheader("🕵️ Detalhamento de Ameaças Conectadas")
            for row in mitre_data:
                with st.expander(f"📌 **{row['ID Técnica']} - {row['Técnica MITRE']}** ({row['Tática']})"):
                    st.write(f"**Contexto:** {row['Descrição do Comportamento']}")
                    st.markdown(f"**Grupos Relacionados:** {row['Grupos Adversários (APTs)']}")
                    st.markdown(f"🔗 [Acessar documentação técnica no MITRE ATT&CK]({row['Link MITRE']})")
        else:
            st.warning("⚠️ Nenhum padrão comportamental foi associado à base do MITRE ATT&CK para o texto fornecido.")

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
# 8. RODAPÉ
# -----------------------------------------------------------------------------
st.markdown("""
    <div class="footer-text">
        CTRDEFENSE.BLOG &copy; 2026 | Platform Architecture for Threat Intelligence V1.0 Beta
    </div>
""", unsafe_allow_html=True)
