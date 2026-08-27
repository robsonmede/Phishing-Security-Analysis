#Analyst Toolkit-Security
# 🛡️ Cyber Threat Research - Caçador de Ameaças V2.3

Aplicação web desenvolvida em **Streamlit** para automação de **Threat Hunting**, **Detection Engineering** e **Triagem de IOCs (Indicadores de Comprometimento)**.

Integrado com as principais APIs do ecossistema de Threat Intelligence (VirusTotal, AbuseIPDB, urlscan.io, GreyNoise e XposedOrNot).

---

## 📋 Pré-requisitos

Antes de começar, certifique-se de ter instalado em sua máquina:

- **Python 3.9** ou superior (Recomendado: Python 3.10 ou 3.11).
- **Git** (opcional, para clonar o repositório).
- **Pip** (gerenciador de pacotes do Python).

---

## 🚀 Passo a Passo para Execução Local

### 1. Clonar ou Baixar o Repositório

Se estiver usando Git:
bash
git clone [https://github.com/seu-usuario/seu-repositorio.git]

## LINUX
python3 -m venv venv
source venv/bin/activate

pip install streamlit pandas requests

pip install -r requirements.txt

VIRUSTOTAL_API_KEY = "SUA_CHAVE_VIRUSTOTAL_AQUI"
ABUSEIPDB_API_KEY = "SUA_CHAVE_ABUSEIPDB_AQUI"
URLSCAN_API_KEY = "SUA_CHAVE_URLSCAN_AQUI"
GREYNOISE_API_KEY = "SUA_CHAVE_GREYNOISE_AQUI" # Opcional

streamlit run app.py

O Streamlit abrirá automaticamente a aplicação no seu navegador padrão no endereço:
👉 http://localhost:8501

Não suba o arquivo .streamlit/secrets.toml para repositórios públicos no GitHub! Adicione .streamlit/secrets.toml ao seu arquivo .gitignore.
As chaves de API tratadas na barra lateral utilizam campos do tipo password para evitar que fiquem visíveis na tela durante gravações ou apresentações.
