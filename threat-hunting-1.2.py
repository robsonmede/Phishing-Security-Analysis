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
    page_title="Cyber Threat Research - Caçador de Ameaças V1.2",
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
    
    default_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")

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

VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", default_key))

# -----------------------------------------------------------------------------
# 4. HEADER DA APLICAÇÃO & STATUS DA API
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Cyber Threat Research - Caçador de Ameaças V1.2</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Threat Hunting, Detection Engineering & Dynamic Threat Mapping</div>', unsafe_allow_html=True)

status_col1, status_col2 = st.columns([3, 1])
with status_col1:
    st.caption("Central Operacional de Caça a Ameaças e Triagem Forense")
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
tab_iocs, tab_hypotheses, tab_queries, tab_entropy, tab_email, tab_decoder, tab_ps_deobf, tab_network = st.tabs([
    "🔍 Extrator & VT",
    "🎯 Central de Hipóteses",
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
# ABA 2: CENTRAL DE HIPÓTESES DE THREAT HUNTING (MITRE ATT&CK)
# =============================================================================
with tab_hypotheses:
    st.header("🎯 Central de Hipóteses de Threat Hunting (MITRE ATT&CK)")
    st.caption("Método estruturado para formulação, execução e validação de hipóteses de caça a ameaças com base nas táticas, técnicas e grupos adversários do MITRE ATT&CK.")

    if "hypotheses_db" not in st.session_state:
        st.session_state["hypotheses_db"] = [
            {
                "id": "HYP-001",
                "title": "Execução Obfuscada via PowerShell EncodedCommand",
                "tactic": "Execution",
                "tech_id": "T1059.001",
                "tech_name": "Command and Scripting Interpreter: PowerShell",
                "hypothesis": "Um atacante está utilizando comandos PowerShell codificados em Base64 para burlar a inspeção estática de logs e baixar scripts maliciosos de segundo estágio em instâncias de produção.",
                "apts": ["APT29 (Cozy Bear)", "FIN7", "Lazarus Group"],
                "data_source": "Process Creation (Event ID 4688 / Sysmon Event ID 1)",
                "status": "Em Investigação",
                "query": "DeviceProcessEvents | where ProcessCommandLine has_any ('-encodedcommand', '-e ', '-enc ')",
                "mitigation": "Habilitar Script Block Logging (Event ID 4104) e restringir o PowerShell via Constrained Language Mode."
            },
            {
                "id": "HYP-002",
                "title": "Dump de Memória do LSASS para Roubo de Credenciais",
                "tactic": "Credential Access",
                "tech_id": "T1003.001",
                "tech_name": "OS Credential Dumping: LSASS Memory",
                "hypothesis": "O adversário obteve acesso local de administrador e está tentando extrair credenciais em texto claro/hashes NTLM da memória do processo lsass.exe utilizando Mimikatz ou procdump.",
                "apts": ["APT32", "Threat Group-3390", "Lazarus Group"],
                "data_source": "Process Access (Sysmon Event ID 10) / Process Termination",
                "status": "Confirmada (Invasão)",
                "query": "TargetImage endswith 'lsass.exe' and GrantedAccess in ('0x1410', '0x1010', '0x1f0fff')",
                "mitigation": "Ativar Windows Defender Credential Guard e isolar a máquina comprometida via EDR."
            },
            {
                "id": "HYP-003",
                "title": "Persistência via Chaves de Registro Run / Startup",
                "tactic": "Persistence",
                "tech_id": "T1547.001",
                "tech_name": "Boot or Logon Autostart Execution: Registry Run Keys",
                "hypothesis": "Para manter acesso persistente no ambiente após a reinicialização, o malware injetou caminhos de executáveis na chave HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
                "apts": ["APT33", "Wizard Spider"],
                "data_source": "Registry Modifications (Sysmon Event ID 12/13)",
                "status": "Não Detectada (Falso Positivo)",
                "query": "DeviceRegistryEvents | where RegistryKey has 'CurrentVersion\\\\Run'",
                "mitigation": "Auditar modificações de chaves autorun e implementar controle de aplicação via AppLocker/WDAC."
            }
        ]

    hyp_df = pd.DataFrame(st.session_state["hypotheses_db"])
    
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    col_m1.metric("Total de Hipóteses", len(hyp_df))
    col_m2.metric("Em Investigação", len(hyp_df[hyp_df["status"] == "Em Investigação"]))
    col_m3.metric("Confirmadas (Ameaça)", len(hyp_df[hyp_df["status"] == "Confirmada (Invasão)"]))
    col_m4.metric("Falsos Positivos / Limpas", len(hyp_df[hyp_df["status"] == "Não Detectada (Falso Positivo)"]))

    st.divider()

    with st.expander("➕ **Formular Nova Hipótese de Threat Hunting**", expanded=False):
        with st.form("form_new_hypothesis"):
            h_title = st.text_input("Título da Hipótese:", placeholder="Ex: Uso ilícito do BITSAdmin para transferência de ferramentas")
            
            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                h_tactic = st.selectbox("Tática MITRE:", ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"])
            with f_col2:
                h_tech_id = st.text_input("ID da Técnica (Ex: T1105):")
            with f_col3:
                h_tech_name = st.text_input("Nome da Técnica (Ex: Ingress Tool Transfer):")
                
            h_text = st.text_area("Descrição da Hipótese (Se [Ameaça], então [Técnica/Comportamento] em [Fonte de Dados]):", height=80)
            
            f_col4, f_col5 = st.columns(2)
            with f_col4:
                h_apts = st.text_input("APTs Suspeitas (separadas por vírgula):", placeholder="Ex: APT29, Kimsuky")
            with f_col5:
                h_data = st.text_input("Fonte de Logs Necessária:", placeholder="Ex: Event ID 4688, Network Flow Logs")

            h_query = st.text_area("Query de Detecção (KQL/EQL/SPL):", height=60, placeholder="Ex: DeviceNetworkEvents | where InitiatingProcessFileName == 'bitsadmin.exe'")
            h_mitigation = st.text_input("Ação de Mitigação / Resposta:")

            if st.form_submit_button("Salvar Hipótese"):
                if h_title and h_tech_id:
                    new_hyp = {
                        "id": f"HYP-00{len(st.session_state['hypotheses_db']) + 1}",
                        "title": h_title,
                        "tactic": h_tactic,
                        "tech_id": h_tech_id.upper(),
                        "tech_name": h_tech_name,
                        "hypothesis": h_text,
                        "apts": [a.strip() for a in h_apts.split(",") if a.strip()],
                        "data_source": h_data,
                        "status": "Em Investigação",
                        "query": h_query,
                        "mitigation": h_mitigation
                    }
                    st.session_state["hypotheses_db"].append(new_hyp)
                    st.success("Nova hipótese cadastrada com sucesso!")
                    st.rerun()
                else:
                    st.error("Preencha pelo menos o Título e o ID da Técnica MITRE.")

    st.subheader("📋 Matriz Operacional de Hipóteses")
    
    display_df = pd.DataFrame([{
        "ID": h["id"],
        "Título": h["title"],
        "Tática": h["tactic"],
        "Técnica MITRE": f"{h['tech_id']} - {h['tech_name']}",
        "APTs Mapeadas": ", ".join(h["apts"]),
        "Status": h["status"]
    } for h in st.session_state["hypotheses_db"]])

    st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("🔬 Execução & Detalhamento da Caça")
    
    selected_hyp_id = st.selectbox(
        "Selecione uma hipótese para analisar ou atualizar o status:",
        options=[h["id"] for h in st.session_state["hypotheses_db"]],
        format_func=lambda x: f"{x} - {next(item['title'] for item in st.session_state['hypotheses_db'] if item['id'] == x)}"
    )

    hyp_detail = next(item for item in st.session_state["hypotheses_db"] if item["id"] == selected_hyp_id)

    d_col1, d_col2 = st.columns([2, 1])
    
    with d_col1:
        st.markdown(f"### {hyp_detail['id']}: {hyp_detail['title']}")
        st.markdown(f"**Teoria da Caça:** {hyp_detail['hypothesis']}")
        st.markdown(f"**Tática / Técnica:** `{hyp_detail['tactic']}` — **[{hyp_detail['tech_id']}] {hyp_detail['tech_name']}**")
        st.markdown(f"**Fonte de Dados Recomendada:** `{hyp_detail['data_source']}`")
        
        st.markdown("**Query de Busca no SIEM/EDR:**")
        st.code(hyp_detail["query"], language="sql")

        st.markdown(f"**Plano de Mitigação/Contenção:** {hyp_detail['mitigation']}")

    with d_col2:
        st.markdown("#### ⚙️ Controle de Investigação")
        
        new_status = st.selectbox(
            "Status da Caça:",
            ["Em Investigação", "Confirmada (Invasão)", "Não Detectada (Falso Positivo)"],
            index=["Em Investigação", "Confirmada (Invasão)", "Não Detectada (Falso Positivo)"].index(hyp_detail["status"])
        )
        
        if new_status != hyp_detail["status"]:
            hyp_detail["status"] = new_status
            st.success("Status atualizado!")
            st.rerun()

        st.markdown("**Ameaças/APTs Associadas:**")
        for apt in hyp_detail["apts"]:
            st.markdown(f"- 🥷 [{apt}](https://attack.mitre.org/search?q={urllib.parse.quote(apt)})")

        st.markdown("---")
        st.markdown(f"🔗 [Documentação Técnica MITRE ATT&CK](https://attack.mitre.org/techniques/{hyp_detail['tech_id'].replace('.', '/')}/)")

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
        CTRDEFENSE.BLOG &copy; 2026 | Cyber Threat Research - Caçador de Ameaças V1.2 (Threat Hunting)
    </div>
""", unsafe_allow_html=True)
