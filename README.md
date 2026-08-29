# Caçador de Ameaças V3.9

⚖️ Responsabilidade do usuário

O usuário é integralmente responsável pelas consultas realizadas e pelo uso dos resultados obtidos.

As informações fornecidas pelas fontes de inteligência podem estar incompletas, desatualizadas, incorretas ou sujeitas a alterações. Os resultados devem ser tratados como informações de apoio e, quando necessário, validados por fontes oficiais ou pelos responsáveis pelos ativos.

O desenvolvedor da ferramenta não se responsabiliza por:

Uso indevido da aplicação;
Consultas realizadas sem autorização;
Violação de legislação, contratos ou políticas internas;
Danos decorrentes da interpretação ou utilização dos resultados;
Tratamento irregular de dados pessoais;
Ações realizadas pelo usuário com base nas informações apresentadas pela ferramenta.
📌 Princípio de uso

Consulte somente aquilo que você possui autorização para consultar e utilize os resultados somente para a finalidade legítima para a qual foram obtidos.

Ao utilizar esta ferramenta, o usuário declara estar ciente de suas responsabilidades legais, técnicas e éticas, comprometendo-se a respeitar a LGPD, legislação aplicável, políticas de segurança, termos de uso das fontes consultadas e os princípios de Responsible Disclosure e Ethical Hacking.

🛡️ Cyber Threat Research - Caçador de Ameaças V3.9
Aplicação web desenvolvida em Streamlit para automação de Threat Hunting, Detection Engineering e Triagem de IOCs (Indicadores de Comprometimento).

## Integrado com as principais APIs do ecossistema de Threat Intelligence (VirusTotal, AbuseIPDB, urlscan.io e XposedOrNot).

📋 Pré-requisitos
Antes de começar, certifique-se de ter instalado em sua máquina:

Python 3.9 ou superior (Recomendado: Python 3.10 ou 3.11).
Git (opcional, para clonar o repositório).
Pip (gerenciador de pacotes do Python).
🚀 Passo a Passo para Execução Local
## 1. Clonar ou Baixar o Repositório
git clone projeto.git

## LINUX
python3 -m venv venv source venv/bin/activate

pip install streamlit pandas requests

pip install -r requirements.txt


streamlit run app.py

## O Streamlit abrirá automaticamente a aplicação no seu navegador padrão no endereço: 👉 http://localhost:8501

