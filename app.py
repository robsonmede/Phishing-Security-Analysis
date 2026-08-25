import re
import pandas as pd
import streamlit as st

# Configuração da página
st.set_page_config(
    page_title="Email Header Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Título e Descrição
st.title("🛡️ Email Header Security Analyzer - by Cyber Threat Research")
st.markdown("Ferramenta de análise rápida de cabeçalhos de e-mail para suporte a equipes de **SOC** e **Análise de Phishing**.")

st.sidebar.header("Instruções")
st.sidebar.info(
    "1. Copie o cabeçalho bruto (Raw Header) do e-mail suspeito.\n"
    "2. Cole no campo ao lado.\n"
    "3. Clique em **Analisar Cabeçalho** para extrair as autenticações e rota de rede."
)

# Entrada do cabeçalho
raw_header = st.text_area("Cole o cabeçalho bruto do e-mail (Raw Header) aqui:", height=220)

def parse_authentication(header_text):
    """Extrai os status de SPF, DKIM e DMARC do cabeçalho."""
    auth_results = {
        "SPF": "Não encontrado",
        "DKIM": "Não encontrado",
        "DMARC": "Não encontrado"
    }
    
    # Regex para capturar os resultados de autenticação
    spf_match = re.search(r'spf=(\w+)', header_text, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(\w+)', header_text, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(\w+)', header_text, re.IGNORECASE)
    
    if spf_match:
        auth_results["SPF"] = spf_match.group(1).upper()
    if dkim_match:
        auth_results["DKIM"] = dkim_match.group(1).upper()
    if dmarc_match:
        auth_results["DMARC"] = dmarc_match.group(1).upper()
        
    return auth_results

def parse_hops(header_text):
    """Extrai os servidores por onde o e-mail transitou (linhas Received)."""
    hops = []
    received_lines = re.findall(r'Received:\s*from\s+(.*?)(?=\n\S|\Z)', header_text, re.DOTALL | re.IGNORECASE)
    
    for i, line in enumerate(received_lines, start=1):
        clean_line = " ".join(line.split())
        hops.append({"Salto (#)": i, "Detalhes do Servidor / IP": clean_line[:120] + "..." if len(clean_line) > 120 else clean_line})
        
    return pd.DataFrame(hops)

if st.button("Analisar Cabeçalho", type="primary"):
    if not raw_header.strip():
        st.warning("Por favor, cole um cabeçalho de e-mail válido antes de analisar.")
    else:
        st.subheader("1. Resultado das Verificações de Autenticação")
        auth_data = parse_authentication(raw_header)
        
        col1, col2, col3 = st.columns(3)
        
        # Exibe os cartões de métricas com cores baseadas no resultado
        with col1:
            st.metric(
                label="Status SPF", 
                value=auth_data["SPF"], 
                delta="PASS" if auth_data["SPF"] == "PASS" else "-FAIL/ALERT",
                delta_color="normal" if auth_data["SPF"] == "PASS" else "inverse"
            )
        with col2:
            st.metric(
                label="Status DKIM", 
                value=auth_data["DKIM"], 
                delta="PASS" if auth_data["DKIM"] == "PASS" else "-FAIL/ALERT",
                delta_color="normal" if auth_data["DKIM"] == "PASS" else "inverse"
            )
        with col3:
            st.metric(
                label="Status DMARC", 
                value=auth_data["DMARC"], 
                delta="PASS" if auth_data["DMARC"] == "PASS" else "-FAIL/ALERT",
                delta_color="normal" if auth_data["DMARC"] == "PASS" else "inverse"
            )
            
        st.divider()
        
        st.subheader("2. Rota de Saltos de Rede (Network Hops)")
        df_hops = parse_hops(raw_header)
        
        if not df_hops.empty:
            st.dataframe(df_hops, use_container_width=True)
        else:
            st.info("Nenhuma linha 'Received:' foi identificada no cabeçalho fornecido.")
st.markdown("TOOL BLUE TEAM - SOC BY Cyber Threat Research - https://ctrdefense.blog")
