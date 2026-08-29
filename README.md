# Caçador de Ameaças V3.8

🛡️ Cyber Threat Research - Caçador de Ameaças V3.7
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

⚠️ DISCLAIMER — USO RESPONSÁVEL DA FERRAMENTA

Esta ferramenta foi desenvolvida para fins educacionais, de pesquisa, Cyber Threat Intelligence (CTI), OSINT, análise de vulnerabilidades e apoio à segurança da informação, devendo ser utilizada exclusivamente de forma legítima, ética e autorizada.

🔐 Proteção de Dados e LGPD

As consultas realizadas por meio desta aplicação devem observar a Lei nº 13.709/2018 — Lei Geral de Proteção de Dados Pessoais (LGPD) e demais normas aplicáveis à proteção de dados.

O usuário é responsável por garantir que qualquer tratamento, consulta, armazenamento, correlação ou compartilhamento de dados pessoais possua base legal adequada, finalidade legítima, necessidade e proporcionalidade.

Não utilize a ferramenta para:

Coletar ou consultar dados pessoais sem finalidade legítima ou base legal;
Realizar perseguição, monitoramento ou investigação indevida de pessoas;
Obter, correlacionar ou divulgar informações pessoais de forma abusiva;
Realizar profiling ou tomada de decisões automatizadas de maneira incompatível com a legislação;
Armazenar informações pessoais além do período ou finalidade necessários;
Compartilhar dados obtidos nas consultas de forma incompatível com sua finalidade original.
🌐 Consultas de infraestrutura e ativos

Consultas relacionadas a domínios, endereços IP, certificados, DNS, WHOIS/RDAP, CVEs, reputação, inteligência de ameaças e serviços expostos devem ser realizadas somente para fins legítimos, como:

Ativos pertencentes ao usuário ou à organização;
Ambientes para os quais exista autorização expressa;
Atividades de defesa cibernética, SOC, CTI, Threat Hunting ou resposta a incidentes;
Pesquisas acadêmicas ou educacionais dentro de ambientes autorizados;
Análise de informações disponibilizadas publicamente de maneira legítima.
🛡️ Consultas passivas

A aplicação prioriza mecanismos de coleta e enriquecimento passivo, utilizando informações disponibilizadas por fontes públicas e serviços de inteligência, como RDAP/WHOIS, NVD/CVE, Shodan InternetDB e outras fontes autorizadas.

Essas consultas não devem ser interpretadas como autorização para testar, explorar ou acessar sistemas de terceiros.

🚫 Scanning ativo

A ferramenta não deve ser utilizada para realizar varreduras ativas, exploração de vulnerabilidades, enumeração invasiva, tentativa de autenticação ou qualquer outro teste contra ativos de terceiros sem autorização prévia e expressa.

A ausência de uma restrição técnica na aplicação não constitui autorização para executar atividades contra sistemas que não pertençam ao usuário ou para os quais ele não possua autorização.

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
