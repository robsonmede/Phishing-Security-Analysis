# -----------------------------------------------------------------------------
# GERENCIAMENTO SEGURO DA API KEY (INTERFACE + FALLBACK SECRETS)
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔑 Configurações de API")
    
    # Busca chave padrão do secretos se existir
    default_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")

    # Campo de texto tipo password para ocultar a chave na interface
    user_vt_key = st.text_input(
        "VirusTotal API Key:",
        value=st.session_state.get("vt_key_input", default_key),
        type="password",
        help="Insira sua chave API do VirusTotal v3 para habilitar as consultas automáticas.",
        key="vt_key_input"
    )

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("💾 Salvar Chave", use_container_width=True):
            st.session_state["active_vt_key"] = user_vt_key
            st.success("Chave salva!")
            st.rerun()

    with col_btn2:
        if st.button("🗑️ Limpar", use_container_width=True):
            st.session_state["vt_key_input"] = ""
            st.session_state["active_vt_key"] = ""
            st.warning("Chave removida!")
            st.rerun()

    st.divider()

# Define a chave ativa priorizando o que foi digitado pelo usuário na tela
VT_API_KEY = st.session_state.get("active_vt_key", st.session_state.get("vt_key_input", default_key))

# Status visual no cabeçalho da aplicação
status_col1, status_col2 = st.columns([3, 1])
with status_col1:
    st.caption("Central de Análise, Threat Hunting e Triagem Diária")
with status_col2:
    if VT_API_KEY and VT_API_KEY != "sua_chave_api_do_virustotal_aqui":
        st.success("🟢 API VirusTotal Conectada", icon="✅")
    else:
        st.warning("🟡 API VirusTotal Ausente", icon="⚠️")
