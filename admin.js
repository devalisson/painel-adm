const cyberTools = {
    OFFENSIVE: [
        { name: "Metasploit", os: ["win", "lin", "termux"], desc: "Plataforma de teste de invasão mais usada do mundo.", install: { lin: "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall", win: "Baixe o instalador .msi no site da Rapid7.", termux: "pkg install unstable-repo && pkg install metasploit" }, repo: "https://github.com/rapid7/metasploit-framework" },
        { name: "Nmap", os: ["win", "lin", "termux"], desc: "Scanner de rede para descoberta de hosts e serviços.", install: { lin: "sudo apt-get install nmap", win: "Baixe o instalador .exe em nmap.org", termux: "pkg install nmap" }, repo: "https://github.com/nmap/nmap" },
        { name: "SQLmap", os: ["win", "lin", "termux"], desc: "Ferramenta automática para injeção de SQL.", install: { lin: "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev", win: "git clone https://github.com/sqlmapproject/sqlmap.git (Requer Python)", termux: "pkg install python && git clone https://github.com/sqlmapproject/sqlmap.git" }, repo: "https://github.com/sqlmapproject/sqlmap" },
        { name: "Hydra", os: ["win", "lin", "termux"], desc: "Cracker de login de rede paralelo e rápido.", install: { lin: "sudo apt-get install hydra", win: "Use Hydra via WSL ou Cygwin.", termux: "pkg install hydra" }, repo: "https://github.com/vanhauser-thc/thc-hydra" },
        { name: "Hashcat", os: ["win", "lin"], desc: "O cracker de senhas mais rápido do mundo.", install: { lin: "sudo apt-get install hashcat", win: "Baixe os binários do Hashcat no site oficial.", termux: "Não suportado (Requer drivers de GPU)." }, repo: "https://github.com/hashcat/hashcat" },
        { name: "Bettercap", os: ["lin", "termux"], desc: "Framework canivete suíço para ataques de rede.", install: { lin: "sudo apt install bettercap", win: "Use dentro de uma VM Linux ou WSL.", termux: "pkg install bettercap" }, repo: "https://github.com/bettercap/bettercap" },
        { name: "Gitleaks", os: ["win", "lin", "termux"], desc: "Scanner de segredos em repositórios Git.", install: { lin: "brew install gitleaks", win: "Baixe via GitHub Releases.", termux: "pkg install gitleaks" }, repo: "https://github.com/gitleaks/gitleaks" },
        { name: "Empire", os: ["lin"], desc: "C2 framework pós-exploração para PowerShell e Python.", install: { lin: "git clone --recursive https://github.com/BC-SECURITY/Empire.git && cd Empire && sudo ./setup/install.sh", win: "Use uma VPS/VM Linux dedicada.", termux: "Instalação complexa. Recomendado Linux nativo." }, repo: "https://github.com/BC-SECURITY/Empire" },
        { name: "BloodHound", os: ["win", "lin"], desc: "Analisa relações de Active Directory.", install: { lin: "apt install bloodhound", win: "Baixe a GUI do BloodHound e use com SharpHound.", termux: "Não aplicável." }, repo: "https://github.com/BloodHoundAD/BloodHound" },
        { name: "OWASP ZAP", os: ["win", "lin"], desc: "Scanner de segurança web dinâmico (DAST).", install: { lin: "sudo snap install zaproxy --classic", win: "Baixe o instalador no site da OWASP.", termux: "Não recomendado para mobile." }, repo: "https://github.com/zaproxy/zaproxy" },
        { name: "Burp Suite", os: ["win", "lin"], desc: "Ferramenta líder para testes de segurança web.", install: { lin: "Baixe o instalador .sh em PortSwigger.net", win: "Baixe o .exe em PortSwigger.net", termux: "Não suportado nativamente." }, repo: "https://github.com/PortSwigger/burp-suite" },
        { name: "Aircrack-ng", os: ["lin", "termux"], desc: "Conjunto de ferramentas para auditoria de redes sem fio.", install: { lin: "sudo apt install aircrack-ng", win: "Use via WSL com drivers compatíveis.", termux: "pkg install aircrack-ng" }, repo: "https://github.com/aircrack-ng/aircrack-ng" },
        { name: "Wifite2", os: ["lin"], desc: "Script automatizado para ataques em redes Wi-Fi.", install: { lin: "sudo apt install wifite", win: "Não suportado nativamente.", termux: "Requer root e drivers wireless." }, repo: "https://github.com/derv82/wifite2" },
        { name: "Commix", os: ["win", "lin", "termux"], desc: "Exploração automática de falhas de Command Injection.", install: { lin: "pip install commix", win: "pip install commix", termux: "pip install commix" }, repo: "https://github.com/commixproject/commix" },
        { name: "Responder", os: ["lin"], desc: "Envenenador LLMNR, NBT-NS e MDNS.", install: { lin: "sudo apt install responder", win: "Não suportado nativamente.", termux: "Não recomendado." }, repo: "https://github.com/lgandx/Responder" },
        { name: "Searchsploit", os: ["win", "lin", "termux"], desc: "Interface de linha de comando para o Exploit-DB.", install: { lin: "sudo apt install exploitdb", win: "git clone https://github.com/offensive-security/exploitdb.git", termux: "pkg install exploitdb" }, repo: "https://github.com/offensive-security/exploitdb" },
        { name: "Beef", os: ["lin"], desc: "Framework de exploração de navegadores (XSS).", install: { lin: "sudo apt install beef-xss", win: "Use via Docker ou VM Linux.", termux: "Instalação complexa via Ruby." }, repo: "https://github.com/beefproject/beef" },
        { name: "Covenant", os: ["win", "lin"], desc: "C2 framework .NET focado em Red Teaming.", install: { lin: "dotnet run --project Covenant", win: "dotnet run --project Covenant", termux: "Não suportado." }, repo: "https://github.com/cobbr/Covenant" },
        { name: "EvilGinx2", os: ["lin"], desc: "Framework de phishing avançado para bypass de 2FA.", install: { lin: "go install github.com/kgretzky/evilginx2@latest", win: "Instale via WSL.", termux: "Não recomendado." }, repo: "https://github.com/kgretzky/evilginx2" },
        { name: "CrackMapExec", os: ["win", "lin"], desc: "Canivete suíço para pentest em redes Active Directory.", install: { lin: "pip install crackmapexec", win: "pip install crackmapexec", termux: "Não recomendado." }, repo: "https://github.com/byt3bl33d3r/CrackMapExec" }
    ],
    DEFENSIVE: [
        { name: "Wazuh", os: ["lin"], desc: "Plataforma de segurança XDR e SIEM.", install: { lin: "curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash wazuh-install.sh -a", win: "Instale apenas o Agente Wazuh.", termux: "Não suportado." }, repo: "https://github.com/wazuh/wazuh" },
        { name: "Snort", os: ["lin"], desc: "Sistema de detecção de intrusão de rede.", install: { lin: "sudo apt-get install snort", win: "Baixe o Snort para Windows no site oficial.", termux: "Instável no Termux." }, repo: "https://github.com/snort3/snort3" },
        { name: "Suricata", os: ["lin"], desc: "Motor de IDS/IPS de rede de alto desempenho.", install: { lin: "sudo apt install suricata", win: "Use o instalador MSI do Suricata.", termux: "Não recomendado." }, repo: "https://github.com/OISF/suricata" },
        { name: "Security Onion", os: ["lin"], desc: "Linux focado em monitoramento de segurança.", install: { lin: "Baixe a ISO e instale como SO principal.", win: "Use como uma Máquina Virtual.", termux: "Não é possível." }, repo: "https://github.com/SecurityOnionSolutions/securityonion" },
        { name: "ClamAV", os: ["win", "lin", "termux"], desc: "Mecanismo antivírus de código aberto.", install: { lin: "sudo apt-get install clamav", win: "Baixe o ClamWin ou ClamAV para Windows.", termux: "pkg install clamav" }, repo: "https://github.com/Cisco-Talos/clamav" },
        { name: "Zeek", os: ["lin"], desc: "Poderoso framework de análise de tráfego.", install: { lin: "sudo apt install zeek", win: "Não suportado nativamente.", termux: "Instável." }, repo: "https://github.com/zeek/zeek" },
        { name: "Fail2Ban", os: ["lin"], desc: "Protege contra ataques de força bruta.", install: { lin: "sudo apt-get install fail2ban", win: "Não aplicável ao Windows nativo.", termux: "Não recomendado." }, repo: "https://github.com/fail2ban/fail2ban" },
        { name: "Velociraptor", os: ["win", "lin"], desc: "Ferramenta de monitoramento de endpoints e DFIR.", install: { lin: "Baixe o binário e execute.", win: "Baixe o .exe e execute como Admin.", termux: "Não aplicável." }, repo: "https://github.com/Velocidex/velociraptor" },
        { name: "ModSecurity", os: ["lin"], desc: "WAF (Web Application Firewall) open source.", install: { lin: "git clone https://github.com/SpiderLabs/ModSecurity && cd ModSecurity && ./build.sh", win: "Não suportado nativamente.", termux: "Não aplicável." }, repo: "https://github.com/SpiderLabs/ModSecurity" },
        { name: "OpenVAS", os: ["lin"], desc: "Scanner de vulnerabilidades completo.", install: { lin: "sudo apt install gvm", win: "Use a VM pré-configurada do Greenbone.", termux: "Não é possível." }, repo: "https://github.com/greenbone/openvas-scanner" },
        { name: "Lynis", os: ["lin", "termux"], desc: "Ferramenta de auditoria de segurança para sistemas Unix.", install: { lin: "sudo apt install lynis", win: "Não suportado (apenas Unix).", termux: "pkg install lynis" }, repo: "https://github.com/CISOfy/lynis" },
        { name: "Rkhunter", os: ["lin"], desc: "Scanner de rootkits, backdoors e exploits locais.", install: { lin: "sudo apt install rkhunter", win: "Não disponível.", termux: "Instável." }, repo: "https://github.com/rkhunter/rkhunter" },
        { name: "CrowdSec", os: ["win", "lin"], desc: "Ecosistema de segurança colaborativo baseado em IP.", install: { lin: "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash", win: "Baixe o instalador MSI.", termux: "Não suportado." }, repo: "https://github.com/crowdsecurity/crowdsec" },
        { name: "Graylog", os: ["lin"], desc: "Gerenciamento centralizado de logs.", install: { lin: "Docker run graylog/graylog", win: "Use Docker Desktop.", termux: "Não suportado." }, repo: "https://github.com/Graylog2/graylog2-server" },
        { name: "OSSEC", os: ["win", "lin"], desc: "HIDS (Intrusion Detection System) baseado em host.", install: { lin: "sudo apt install ossec-hids-server", win: "Instale o OSSEC Agent (.exe).", termux: "Não suportado." }, repo: "https://github.com/ossec/ossec-hids" },
        { name: "Arkime", os: ["lin"], desc: "Captura de pacotes e busca indexada de tráfego.", install: { lin: "npm install -g arkime", win: "Não suportado nativamente.", termux: "Não aplicável." }, repo: "https://github.com/arkime/arkime" },
        { name: "Yara-Forge", os: ["win", "lin", "termux"], desc: "Repositório otimizado de regras YARA para defesa.", install: { lin: "git clone https://github.com/YARA-Forge/rules.git", win: "Acesse via GitHub.", termux: "git clone no diretório local." }, repo: "https://github.com/YARA-Forge/rules" },
        { name: "Moloch", os: ["lin"], desc: "Ferramenta de visualização e captura de pacotes (Antiga Arkime).", install: { lin: "Siga o guia de build no README.", win: "Não suportado.", termux: "Não aplicável." }, repo: "https://github.com/arkime/arkime" },
        { name: "Glider", os: ["lin"], desc: "Proxy reverso focado em segurança e evasão.", install: { lin: "go install github.com/nadoo/glider@latest", win: "Binário disponível em Releases.", termux: "pkg install glider" }, repo: "https://github.com/nadoo/glider" },
        { name: "UFW", os: ["lin"], desc: "Uncomplicated Firewall para fácil gestão de porta.", install: { lin: "sudo apt install ufw", win: "Use Windows Firewall nativo.", termux: "Não recomendável." }, repo: "https://github.com/canonical/ufw" }
    ],
    APPSEC: [
        { name: "Semgrep", os: ["win", "lin", "termux"], desc: "Scanner estático para encontrar bugs rapidamente.", install: { lin: "pip install semgrep", win: "pip install semgrep", termux: "pkg install python && pip install semgrep" }, repo: "https://github.com/returntocorp/semgrep" },
        { name: "Bandit", os: ["win", "lin", "termux"], desc: "Encontra problemas de segurança em código Python.", install: { lin: "pip install bandit", win: "pip install bandit", termux: "pip install bandit" }, repo: "https://github.com/PyCQA/bandit" },
        { name: "TruffleHog", os: ["win", "lin", "termux"], desc: "Busca por segredos e senhas em Git e nuvem.", install: { lin: "brew install trufflehog", win: "Baixe o binário .exe.", termux: "pip install trufflehog" }, repo: "https://github.com/trufflesecurity/trufflehog" },
        { name: "MobSF", os: ["win", "lin"], desc: "Framework de análise de segurança mobile.", install: { lin: "git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git && ./setup.sh", win: "Use setup.bat (Requer Python/Java/VStudio)", termux: "Não é possível." }, repo: "https://github.com/MobSF/Mobile-Security-Framework-MobSF" },
        { name: "DefectDojo", os: ["win", "lin"], desc: "Gestão centralizada de vulnerabilidades.", install: { lin: "docker-compose up -d --build", win: "Use o Docker Desktop.", termux: "Não é possível." }, repo: "https://github.com/DefectDojo/django-DefectDojo" },
        { name: "Horusec", os: ["win", "lin", "termux"], desc: "Orquestrador de ferramentas SAST dinâmico.", install: { lin: "curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/master/deployments/scripts/install.sh | bash", win: "Baixe o instalador .exe.", termux: "Use o script de instalação do Linux via curl." }, repo: "https://github.com/ZupIT/horusec" },
        { name: "KICS", os: ["win", "lin"], desc: "Scanning de infraestrutura como código (IaC).", install: { lin: "docker pull checkmarx/kics:latest", win: "docker pull checkmarx/kics:latest", termux: "Não suportado." }, repo: "https://github.com/Checkmarx/kics" },
        { name: "Dependency-Check", os: ["win", "lin"], desc: "Identifica dependências vulneráveis.", install: { lin: "brew install dependency-check", win: "Baixe o ZIP e execute o .bat", termux: "Instável." }, repo: "https://github.com/jeremylong/DependencyCheck" },
        { name: "SonarQube", os: ["win", "lin"], desc: "Inspeção contínua de qualidade e segurança.", install: { lin: "docker run sonarqube", win: "docker run sonarqube", termux: "Não é possível." }, repo: "https://github.com/SonarSource/sonarqube" },
        { name: "Snyk", os: ["win", "lin", "termux"], desc: "CLI para encontrar e corrigir vulnerabilidades.", install: { lin: "npm install -g snyk", win: "npm install -g snyk", termux: "npm install -g snyk" }, repo: "https://github.com/snyk/snyk" },
        { name: "Brakeman", os: ["win", "lin"], desc: "Scanner de segurança estático para Ruby on Rails.", install: { lin: "gem install brakeman", win: "gem install brakeman", termux: "gem install brakeman" }, repo: "https://github.com/presidentbeef/brakeman" },
        { name: "Nuclei", os: ["win", "lin", "termux"], desc: "Scanner de modelos rápido e personalizável.", install: { lin: "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", win: "Baixe o binário releases.", termux: "pkg install nuclei" }, repo: "https://github.com/projectdiscovery/nuclei" },
        { name: "Arachni", os: ["win", "lin"], desc: "Scanner de segurança web de alto desempenho.", install: { lin: "Baixe o pacote compilado e execute.", win: "Baixe os binários para Windows.", termux: "Não suportado." }, repo: "https://github.com/Arachni/arachni" },
        { name: "Wapiti", os: ["win", "lin", "termux"], desc: "Scanner de vulnerabilidade web de caixa preta.", install: { lin: "pip3 install wapiti3", win: "pip3 install wapiti3", termux: "pip3 install wapiti3" }, repo: "https://github.com/wapiti-scanner/wapiti" },
        { name: "Nikto2", os: ["win", "lin", "termux"], desc: "Scanner de servidor web clássico.", install: { lin: "sudo apt install nikto", win: "Clone e rode via Perl.", termux: "pkg install nikto" }, repo: "https://github.com/sullo/nikto" },
        { name: "Gitleaks-Action", os: ["lin"], desc: "Action do GitHub para Auditoria de Secrets no CI.", install: { lin: "Adicione ao seu arquivo .github/workflows/main.yml", win: "Não aplicável localmente.", termux: "Não aplicável." }, repo: "https://github.com/gitleaks/gitleaks-action" },
        { name: "Sidero", os: ["lin"], desc: "Análise estática de código para infraestrutura IaC.", install: { lin: "curl -sL https://install.sidero.io | sh", win: "Não suportado.", termux: "Não suportado." }, repo: "https://github.com/siderolabs/sidero" },
        { name: "Checkmarx-AST", os: ["win", "lin"], desc: "Plataforma de segurança de aplicação em nuvem.", install: { lin: "Instale via CLI oficial.", win: "Baixe o instalador oficial.", termux: "Não atendido." }, repo: "https://github.com/Checkmarx/ast-cli" },
        { name: "Kubescape", os: ["win", "lin"], desc: "Scanner de Kubernetes baseado em frameworks de conformidade.", install: { lin: "curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash", win: "iwr https://raw.githubusercontent.com/.../install.ps1 | iex", termux: "Não disponível." }, repo: "https://github.com/kubescape/kubescape" },
        { name: "Terrascan-CLI", os: ["win", "lin", "termux"], desc: "Lente de segurança para seus recursos em nuvem.", install: { lin: "curl -L https://github.com/.../terrascan.sh | bash", win: "Baixe o binário .exe", termux: "Clone e builde via Go." }, repo: "https://github.com/tenable/terrascan" }
    ],
    CLOUD: [
        { name: "Scout Suite", os: ["win", "lin", "termux"], desc: "Ferramenta de auditoria multi-cloud.", install: { lin: "pip install scoutsuite", win: "pip install scoutsuite", termux: "pip install scoutsuite" }, repo: "https://github.com/nccgroup/ScoutSuite" },
        { name: "Prowler", os: ["win", "lin", "termux"], desc: "Avançado scanner de segurança AWS.", install: { lin: "pip install prowler", win: "pip install prowler", termux: "pip install prowler" }, repo: "https://github.com/prowler-cloud/prowler" },
        { name: "CloudCustodian", os: ["win", "lin", "termux"], desc: "Motor de regras para gerenciar nuvem.", install: { lin: "pip install c7n", win: "pip install c7n", termux: "pip install c7n" }, repo: "https://github.com/cloud-custodian/cloud-custodian" },
        { name: "Checkov", os: ["win", "lin", "termux"], desc: "Scanner de IaC para Terraform e CloudFormation.", install: { lin: "pip install checkov", win: "pip install checkov", termux: "pip install checkov" }, repo: "https://github.com/bridgecrewio/checkov" },
        { name: "Terrascan", os: ["win", "lin", "termux"], desc: "Políticas de segurança para infraestrutura.", install: { lin: "brew install terrascan", win: "Baixe o binário .exe.", termux: "Baixe o binário compilado." }, repo: "https://github.com/accurics/terrascan" },
        { name: "Falco", os: ["lin"], desc: "Segurança em tempo real para containers.", install: { lin: "Instale via script oficial de módulos de kernel.", win: "Use via VM Linux.", termux: "Não suportado." }, repo: "https://github.com/falcosecurity/falco" },
        { name: "Trivy", os: ["win", "lin", "termux"], desc: "Scanner de vulnerabilidades para containers.", install: { lin: "brew install aquasecurity/trivy/trivy", win: "Baixe o instalador .exe.", termux: "Baixe o binário para sua arquitetura." }, repo: "https://github.com/aquasecurity/trivy" },
        { name: "Steampipe", os: ["win", "lin"], desc: "Use SQL para consultar infraestrutura de nuvem.", install: { lin: "brew install turbot/tap/steampipe", win: "Instale via WSL.", termux: "Não suportado." }, repo: "https://github.com/turbot/steampipe" },
        { name: "Pacu", os: ["win", "lin", "termux"], desc: "Framework de exploração de AWS.", install: { lin: "pip3 install pacu", win: "pip3 install pacu", termux: "pip3 install pacu" }, repo: "https://github.com/RhinoSecurityLabs/pacu" },
        { name: "Cartography", os: ["win", "lin"], desc: "Mapeia infraestrutura de nuvem em grafo.", install: { lin: "pip install cartography", win: "pip install cartography", termux: "Instável." }, repo: "https://github.com/lyft/cartography" },
        { name: "Kube-bench", os: ["lin"], desc: "Verifica se o Kubernetes está implantado com segurança.", install: { lin: "job.yaml no cluster K8s.", win: "Não disponível.", termux: "Não aplicável." }, repo: "https://github.com/aquasecurity/kube-bench" },
        { name: "Terragrunt", os: ["win", "lin", "termux"], desc: "Ferramenta helper para manter Terraform DRY.", install: { lin: "brew install terragrunt", win: "Baixe o .exe oficial.", termux: "pkg install terragrunt (Go)" }, repo: "https://github.com/gruntwork-io/terragrunt" },
        { name: "Aqua Security Kube-Hunter", os: ["lin"], desc: "Caça vulnerabilidades de segurança em clusters Kubernetes.", install: { lin: "pip install kube-hunter", win: "Não suportado nativamente.", termux: "Não aplicável." }, repo: "https://github.com/aquasecurity/kube-hunter" },
        { name: "CloudSplaining", os: ["win", "lin"], desc: "IA para análise de permissões de IAM na AWS.", install: { lin: "pip install cloudsplaining", win: "pip install cloudsplaining", termux: "Não disponível." }, repo: "https://github.com/salesforce/cloudsplaining" },
        { name: "Azure-Hunter", os: ["win", "lin"], desc: "Scanner de forense e incidentes para Azure.", install: { lin: "pip install azure-hunter", win: "pip install azure-hunter", termux: "Não recomendado." }, repo: "https://github.com/Cyber-m0nk/azure-hunter" },
        { name: "Hacker-Container", os: ["lin"], desc: "Container Docker pronto para pentest em nuvem.", install: { lin: "docker pull hacker-container", win: "docker pull hacker-container", termux: "Não disponível." }, repo: "https://github.com/miztiik/hacker-container" },
        { name: "Cyscale", os: ["win", "lin"], desc: "Scanner de conformidade Multi-cloud.", install: { lin: "Execute via CLI Cyscale.", win: "Execute via CLI Cyscale.", termux: "Não disponível." }, repo: "https://github.com/cyscale/cyscale-cli" },
        { name: "Driftctl", os: ["win", "lin"], desc: "Detecta desvios de infraestrutura (IaC).", install: { lin: "curl -L https://driftctl.com/install.sh | sh", win: "Baixe o binário releases.", termux: "Não disponível." }, repo: "https://github.com/snyk/driftctl" },
        { name: "Cloudfox", os: ["win", "lin", "termux"], desc: "Exploração rápida de infraestrutura cloud.", install: { lin: "go install github.com/BishopFox/cloudfox@latest", win: "Baixe o executável oficial.", termux: "Clone e builde via Go." }, repo: "https://github.com/BishopFox/cloudfox" },
        { name: "Peirates", os: ["lin"], desc: "Exploração de privilégios de containers Kubernetes.", install: { lin: "Download do binário tar.gz.", win: "Não suportado.", termux: "Não aplicável." }, repo: "https://github.com/inguardians/peirates" }
    ],
    FORENSICS: [
        { name: "Autopsy", os: ["win", "lin"], desc: "Plataforma de forense digital baseada em GUI.", install: { lin: "Baixe o .deb e instale.", win: "Baixe o instalador MSI no site oficial.", termux: "Não é possível." }, repo: "https://github.com/sleuthkit/autopsy" },
        { name: "Volatility", os: ["win", "lin", "termux"], desc: "Framework de análise de memória RAM.", install: { lin: "pip install volatility3", win: "pip install volatility3", termux: "pip install volatility3" }, repo: "https://github.com/volatilityfoundation/volatility3" },
        { name: "Sleuth Kit", os: ["win", "lin", "termux"], desc: "Ferramentas de linha de comando para análise de disco.", install: { lin: "sudo apt-get install sleuthkit", win: "Baixe os binários compilados.", termux: "pkg install sleuthkit" }, repo: "https://github.com/sleuthkit/sleuthkit" },
        { name: "FTK Imager", os: ["win"], desc: "Cria imagens forenses perfeitas.", install: { win: "Baixe no site da AccessData.", lin: "Use via Wine (não recomendado).", termux: "Não é possível." }, repo: "https://github.com/AccessData/FTK-Imager" },
        { name: "GRR", os: ["lin"], desc: "Resposta a incidentes rápida do Google.", install: { lin: "docker run -p 8000:8000 google/grr", win: "Use o Docker Desktop.", termux: "Não é possível." }, repo: "https://github.com/google/grr" },
        { name: "Binwalk", os: ["win", "lin", "termux"], desc: "Analisa e extrai arquivos binários.", install: { lin: "sudo apt-get install binwalk", win: "pip install binwalk", termux: "pkg install binwalk" }, repo: "https://github.com/ReFirmLabs/binwalk" },
        { name: "PhotoRec", os: ["win", "lin", "termux"], desc: "Recupera arquivos apagados de discos.", install: { lin: "sudo apt-get install testdisk", win: "Baixe o TestDisk para Windows.", termux: "pkg install testdisk" }, repo: "https://github.com/cgsecurity/testdisk" },
        { name: "CAINE", os: ["lin"], desc: "Distribuição Live completa de forense.", install: { lin: "Baixe a ISO e dê boot por ela.", win: "Execute em uma VM dedicada.", termux: "Não é possível." }, repo: "https://github.com/CAINE-OS/CAINE" },
        { name: "Magnet RAM Capture", os: ["win"], desc: "Captura rápida de memória RAM.", install: { win: "Baixe e execute o .exe standalone.", lin: "Não aplicável.", termux: "Não aplicável." }, repo: "https://github.com/MagnetForensics" },
        { name: "Wireshark", os: ["win", "lin"], desc: "Analisador de protocolos de rede.", install: { lin: "sudo apt-get install wireshark", win: "Baixe o instalador em Wireshark.org", termux: "Não é possível." }, repo: "https://github.com/wireshark/wireshark" },
        { name: "Bulk Extractor", os: ["win", "lin", "termux"], desc: "Extrai emails, IPs e URLs de imagens de disco.", install: { lin: "sudo apt install bulk-extractor", win: "Instalador disponível no GitHub.", termux: "Compilar do código fonte." }, repo: "https://github.com/simsong/bulk_extractor" },
        { name: "Ghidra", os: ["win", "lin"], desc: "Framework de engenharia reversa da NSA.", install: { lin: "Baixe o ZIP e rode ghidraRun.", win: "Requer Java JDK 17+", termux: "Não aplicável." }, repo: "https://github.com/NationalSecurityAgency/ghidra" },
        { name: "ExifTool", os: ["win", "lin", "termux"], desc: "Lê e escreve metadados em arquivos.", install: { lin: "sudo apt install exiftool", win: "Baixe o executável autônomo.", termux: "pkg install exiftool" }, repo: "https://github.com/exiftool/exiftool" },
        { name: "X-Ways Forensics", os: ["win"], desc: "Ambiente de análise forense avançado (Pago/Demo).", install: { win: "Baixe no site oficial.", lin: "Não suportado nativamente.", termux: "Não aplicável." }, repo: "https://github.com/x-ways" },
        { name: "Radare2", os: ["win", "lin", "termux"], desc: "Canivete suíço para engenharia reversa e forense.", install: { lin: "sudo apt install radare2", win: "Baixe o instalador no GitHub.", termux: "pkg install radare2" }, repo: "https://github.com/radareorg/radare2" },
        { name: "Guymager", os: ["lin"], desc: "Gerador de imagens de disco rápido e open source.", install: { lin: "sudo apt install guymager", win: "Não disponível.", termux: "Não aplicável." }, repo: "https://github.com/guymager/guymager" },
        { name: "DFF (Digital Forensics Framework)", os: ["win", "lin"], desc: "Framework modular para resposta a incidentes.", install: { lin: "Instale via script de build oficial.", win: "Baixe o instalador legado.", termux: "Não aplicável." }, repo: "https://github.com/arxsys/dff" },
        { name: "Afl-fuzz", os: ["lin"], desc: "Fuzzer orientado por cobertura de código.", install: { lin: "sudo apt install afl++", win: "Use via WSL.", termux: "pkg install afl" }, repo: "https://github.com/AFLplusplus/AFLplusplus" },
        { name: "Malzilla", os: ["win"], desc: "Ferramenta para análise de páginas web maliciosas.", install: { win: "Baixe o executável portátil.", lin: "Use via Wine.", termux: "Não aplicável." }, repo: "https://github.com/malzilla" },
        { name: "CyberChef", os: ["win", "lin", "termux"], desc: "Cyber Swiss Army Knife para processamento de dados.", install: { lin: "Abra no navegador (Standalone HTML disponível).", win: "Abra index.html localmente.", termux: "Acesse via browser mobile." }, repo: "https://github.com/gchq/CyberChef" }
    ],
    INTEL: [
        { name: "Maltego", os: ["win", "lin"], desc: "Análise de links e visualização de dados para investigações complexas.", install: { lin: "Baixe o instalador .deb no site oficial.", win: "Baixe o instalador .exe oficial.", termux: "Não suportado." }, repo: "https://www.maltego.com/" },
        { name: "theHarvester", os: ["win", "lin", "termux"], desc: "Coleta de e-mails, subdomínios, hosts e nomes de funcionários de fontes públicas.", install: { lin: "sudo apt install theharvester", win: "git clone https://github.com/laramies/theHarvester.git", termux: "pkg install python && pip install theHarvester" }, repo: "https://github.com/laramies/theHarvester" },
        { name: "Recon-ng", os: ["win", "lin", "termux"], desc: "Framework completo de reconhecimento web escrito em Python.", install: { lin: "sudo apt install recon-ng", win: "pip install recon-ng", termux: "pkg install python && pip install recon-ng" }, repo: "https://github.com/lanmaster53/recon-ng" },
        { name: "SpiderFoot", os: ["win", "lin", "termux"], desc: "Ferramenta de automação de OSINT que integra centenas de fontes de dados.", install: { lin: "pip install spiderfoot", win: "pip install spiderfoot", termux: "pip install spiderfoot" }, repo: "https://github.com/smicallef/spiderfoot" },
        { name: "Shodan", os: ["win", "lin", "termux"], desc: "Motor de busca para dispositivos conectados à Internet das Coisas (IoT).", install: { lin: "pip install shodan", win: "pip install shodan", termux: "pip install shodan" }, repo: "https://github.com/achillean/shodan-python" },
        { name: "Censys", os: ["win", "lin", "termux"], desc: "Busca e análise de ativos de rede e infraestrutura de internet.", install: { lin: "pip install censys", win: "pip install censys", termux: "pip install censys" }, repo: "https://github.com/censys/censys-python" },
        { name: "Fofa", os: ["web"], desc: "Motor de busca focado em ativos de rede (especialmente na China).", install: { web: "Acesse via Navegador." }, repo: "https://fofa.info" },
        { name: "Zoomeye", os: ["win", "lin", "termux"], desc: "Buscador de dispositivos e serviços web para inteligência de ameaças.", install: { lin: "pip install zoomeye", win: "pip install zoomeye", termux: "pip install zoomeye" }, repo: "https://github.com/zoomeye/SDK" },
        { name: "BinaryEdge", os: ["web"], desc: "Plataforma de inteligência de ameaças cibernéticas e monitoramento de ataques.", install: { web: "Acesse via Navegador." }, repo: "https://binaryedge.io" },
        { name: "GreyNoise", os: ["win", "lin", "termux"], desc: "Analisa o ruído da internet para identificar varreduras inofensivas e ataques reais.", install: { lin: "pip install greynoise", win: "pip install greynoise", termux: "pip install greynoise" }, repo: "https://github.com/GreyNoise-Intelligence/pygreynoise" },
        { name: "IntelX", os: ["web"], desc: "Motor de busca e arquivo que indexa dados expostos, vazamentos e darknet.", install: { web: "Acesse via Navegador." }, repo: "https://intelx.io" },
        { name: "Have I Been Pwned", os: ["web"], desc: "Verificação se suas contas e e-mails foram comprometidos em vazamentos de dados.", install: { web: "Acesse via Navegador." }, repo: "https://haveibeenpwned.com" }
    ],
    PESSOAS: [
        { name: "Pipl", os: ["web"], desc: "Busca de informações de identidade e contatos em nível profissional.", install: { web: "Acesse via Navegador." }, repo: "https://pipl.com" },
        { name: "Spokeo", os: ["web"], desc: "Buscador de pessoas que agrega dados de registros públicos e redes sociais.", install: { web: "Acesse via Navegador." }, repo: "https://spokeo.com" },
        { name: "PeekYou", os: ["web"], desc: "Encontra pessoas e seus perfis em diversas redes sociais.", install: { web: "Acesse via Navegador." }, repo: "https://peekyou.com" },
        { name: "TruePeopleSearch", os: ["web"], desc: "Busca gratuita de registros públicos de pessoas (EUA).", install: { web: "Acesse via Navegador." }, repo: "https://truepeoplesearch.com" },
        { name: "Social Catfish", os: ["web"], desc: "Especializado em verificação de identidade online e prevenção de golpes.", install: { web: "Acesse via Navegador." }, repo: "https://socialcatfish.com" },
        { name: "Namechk", os: ["web"], desc: "Verifica a disponibilidade de usernames e domínios em dezenas de sites.", install: { web: "Acesse via Navegador." }, repo: "https://namechk.com" }
    ],
    EMAIL: [
        { name: "Hunter.io", os: ["web"], desc: "Encontra endereços de e-mail corporativos vinculados a qualquer domínio.", install: { web: "Acesse via Navegador." }, repo: "https://hunter.io" },
        { name: "EmailRep", os: ["web"], desc: "Sistema de reputação de e-mail focado em segurança e detecção de fraude.", install: { web: "Acesse via Navegador." }, repo: "https://emailrep.io" },
        { name: "VoilaNorbert", os: ["web"], desc: "Localizador de e-mails para prospecção de vendas e recrutamento.", install: { web: "Acesse via Navegador." }, repo: "https://voilanorbert.com" },
        { name: "Snov.io", os: ["web"], desc: "Plataforma para busca e verificação de e-mails para campanhas.", install: { web: "Acesse via Navegador." }, repo: "https://snov.io" },
        { name: "Phonebook.cz", os: ["web"], desc: "Busca de e-mails e domínios em bancos de dados de vazamentos.", install: { web: "Acesse via Navegador." }, repo: "https://phonebook.cz" }
    ],
    GEO: [
        { name: "Google Earth Pro", os: ["win", "lin"], desc: "Visualização de imagens de satélite de alta resolução e dados geoespaciais.", install: { lin: "Baixe o .deb no site oficial.", win: "Baixe o instalador .exe.", termux: "Não suportado." }, repo: "https://earth.google.com/web" },
        { name: "OpenStreetMap", os: ["web"], desc: "Mapa mundi editável e gratuito construído por voluntários.", install: { web: "Acesse via Navegador." }, repo: "https://www.openstreetmap.org" },
        { name: "Wikimapia", os: ["web"], desc: "Mapa editável que permite marcar e descrever qualquer lugar na Terra.", install: { web: "Acesse via Navegador." }, repo: "https://wikimapia.org" },
        { name: "Sentinel Hub", os: ["web"], desc: "Acesso a imagens de satélite Sentinel em tempo quase real.", install: { web: "Acesse via Navegador." }, repo: "https://www.sentinel-hub.com" },
        { name: "Mapillary", os: ["web"], desc: "Plataforma de imagens de nível de rua colaborativa e aberta.", install: { web: "Acesse via Navegador." }, repo: "https://www.mapillary.com" }
    ],
    EMPRESAS: [
        { name: "OpenCorporates", os: ["web"], desc: "O maior banco de dados aberto de empresas do mundo.", install: { web: "Acesse via Navegador." }, repo: "https://opencorporates.com" },
        { name: "Crunchbase", os: ["web"], desc: "Informações sobre empresas públicas e privadas, investimentos e tendências.", install: { web: "Acesse via Navegador." }, repo: "https://crunchbase.com" },
        { name: "Glassdoor", os: ["web"], desc: "Avaliações de empresas, salários e cultura organizacional por funcionários.", install: { web: "Acesse via Navegador." }, repo: "https://glassdoor.com" },
        { name: "D&B Hoovers", os: ["web"], desc: "Inteligência comercial e dados detalhados sobre milhões de empresas.", install: { web: "Acesse via Navegador." }, repo: "https://www.dnb.com" },
        { name: "Panjiva", os: ["web"], desc: "Dados de comércio global e inteligência de cadeia de suprimentos.", install: { web: "Acesse via Navegador." }, repo: "https://panjiva.com" }
    ],
    TECNICAS: [
        { name: "FOCA", os: ["win"], desc: "Ferramenta para extração de metadados e informações de documentos públicos.", install: { lin: "Requer Mono ou VM Windows.", win: "Baixe o instalador oficial.", termux: "Não suportado." }, repo: "https://github.com/ElevenPaths/FOCA" },
        { name: "Metagoofil", os: ["win", "lin", "termux"], desc: "Extrai metadados de documentos públicos (pdf, doc, xls, etc.) da web.", install: { lin: "sudo apt install metagoofil", win: "pip install metagoofil", termux: "pip install metagoofil" }, repo: "https://github.com/laramies/metagoofil" },
    ],
    VEICULOS: [
        { name: "FlightRadar24", os: ["web"], desc: "Rastreamento de voos em tempo real ao redor do mundo.", install: { web: "Acesse via Navegador." }, repo: "https://www.flightradar24.com" },
        { name: "MarineTraffic", os: ["web"], desc: "Rastreamento de navios e tráfego marítimo global em tempo real.", install: { web: "Acesse via Navegador." }, repo: "https://www.marinetraffic.com" },
        { name: "ADSB-Exchange", os: ["web"], desc: "A maior fonte mundial de dados de voos não filtrados.", install: { web: "Acesse via Navegador." }, repo: "https://www.adsbexchange.com" },
        { name: "VesselFinder", os: ["web"], desc: "Serviço de rastreamento de navios gratuito e mapas de portos.", install: { web: "Acesse via Navegador." }, repo: "https://www.vesselfinder.com" },
        { name: "Planespotters", os: ["web"], desc: "Banco de dados massivo de fotos e dados de frotas de aeronaves.", install: { web: "Acesse via Navegador." }, repo: "https://www.planespotters.net" }
    ],
    DOMINIOS: [
        { name: "Whois.is", os: ["win", "lin", "termux"], desc: "Consulta de registros WHOIS para domínios e IPs.", install: { lin: "Acesse via navegador ou `whois` no terminal.", win: "Acesse via navegador.", termux: "pkg install whois" }, repo: "https://whois.is" },
        { name: "DNSDumpster", os: ["web"], desc: "Pesquisa de registros DNS e mapeamento de subdomínios.", install: { web: "Acesse via Navegador." }, repo: "https://dnsdumpster.com" },
        { name: "ViewDNS.info", os: ["web"], desc: "Conjunto massivo de ferramentas para investigação de domínios e rede.", install: { web: "Acesse via Navegador." }, repo: "https://viewdns.info" },
        { name: "BuiltWith", os: ["web"], desc: "Identifica as tecnologias usadas para construir qualquer site.", install: { web: "Acesse via Navegador." }, repo: "https://builtwith.com" },
        { name: "SpyOnWeb", os: ["web"], desc: "Identifica sites que compartilham o mesmo proprietário (via IDs de analytics/ads).", install: { web: "Acesse via Navegador." }, repo: "https://spyonweb.com" }
    ],
    TELEFONES: [
        { name: "PhoneInfoga", os: ["win", "lin", "termux"], desc: "Ferramenta avançada para escaneamento de números de telefone e coleta de informações.", install: { lin: "curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash", win: "Baixe o binário no GitHub Releases.", termux: "Baixe o binário arm64 no site oficial." }, repo: "https://github.com/sundowndev/phoneinfoga" },
        { name: "Truecaller (Web)", os: ["web"], desc: "Identificação de chamadas e nomes de proprietários de números globais.", install: { web: "Acesse via Navegador." }, repo: "https://www.truecaller.com" },
        { name: "Sync.ME", os: ["web"], desc: "Busca reversa de telefone e identificação de perfis sociais vinculados.", install: { web: "Acesse via Navegador." }, repo: "https://sync.me" },
        { name: "NumVerify", os: ["web"], desc: "API para validação de números de telefone e informações de operadora.", install: { web: "Acesse via Navegador." }, repo: "https://numverify.com" },
        { name: "SpyDialer", os: ["web"], desc: "Busca reversa gratuita de celulares e telefones fixos (EUA).", install: { web: "Acesse via Navegador." }, repo: "https://www.spydialer.com" }
    ],
    CRIPTO: [
        { name: "Blockchain Explorer", os: ["web"], desc: "Visualização e análise de transações e endereços de Bitcoin.", install: { web: "Acesse via Navegador." }, repo: "https://www.blockchain.com/explorer" },
        { name: "Etherscan", os: ["web"], desc: "Explorador de dados e transações para a rede Ethereum.", install: { web: "Acesse via Navegador." }, repo: "https://etherscan.io" },
        { name: "WalletExplorer", os: ["web"], desc: "Rastreamento de carteiras e agrupamento de endereços de criptomoedas.", install: { web: "Acesse via Navegador." }, repo: "https://www.walletexplorer.com" },
        { name: "Crystallize", os: ["win", "lin"], desc: "Ferramenta forense para investigação de transações de criptoativos.", install: { lin: "Acesse via plataforma web.", win: "Acesse via plataforma web.", termux: "Não suportado." }, repo: "https://crystalblockchain.com" },
        { name: "Tornado Cash (History)", os: ["win", "lin", "termux"], desc: "Ferramenta para análise e rastreamento (limítrofe) de transações via mixers.", install: { lin: "Acesse mirrors/arquivos.", win: "Acesse via proxies.", termux: "Acesse via Tor." }, repo: "https://github.com/tornadocash" }
    ],
    DOCUMENTOS: [
        { name: "Scribd", os: ["web"], desc: "Biblioteca digital massiva com milhões de documentos e apresentações públicas.", install: { web: "Acesse via Navegador." }, repo: "https://www.scribd.com" },
        { name: "SlideShare", os: ["web"], desc: "Plataforma de compartilhamento de apresentações corporativas e técnicas.", install: { web: "Acesse via Navegador." }, repo: "https://www.slideshare.net" },
        { name: "Academia.edu", os: ["web"], desc: "Repositório massivo de artigos acadêmicos e documentos de pesquisa.", install: { web: "Acesse via Navegador." }, repo: "https://www.academia.edu" },
        { name: "Wayback Machine", os: ["web"], desc: "Arquivo histórico da internet que permite ver versões antigas de sites e documentos.", install: { web: "Acesse via Navegador." }, repo: "https://archive.org/web/" },
        { name: "Google Scholars", os: ["web"], desc: "Pesquisa avançada em literatura acadêmica e documentos técnicos.", install: { web: "Acesse via Navegador." }, repo: "https://scholar.google.com" }
    ],
    IA: [
        { name: "ChatGPT (OpenAI)", os: ["web"], desc: "IA avançada para análise de dados, tradução e geração de scripts OSINT.", install: { web: "Acesse via Navegador." }, repo: "https://chat.openai.com" },
        { name: "Perplexity AI", os: ["web"], desc: "Motor de busca baseado em IA que fornece fontes diretas para as respostas.", install: { web: "Acesse via Navegador." }, repo: "https://www.perplexity.ai" },
        { name: "Claude (Anthropic)", os: ["web"], desc: "Modelo de linguagem focado em segurança para análise complexa de textos.", install: { web: "Acesse via Navegador." }, repo: "https://www.anthropic.com" },
        { name: "Gemini (Google)", os: ["web"], desc: "IA multimodal integrada aos serviços do Google para pesquisas rápidas.", install: { web: "Acesse via Navegador." }, repo: "https://gemini.google.com" }
    ],
    EDUCACAO: [
        { name: "OSINT Framework", os: ["web"], desc: "O guia interativo mais completo para ferramentas e recursos OSINT.", install: { web: "Acesse via Navegador." }, repo: "https://osintframework.com" },
        { name: "Bellingcat Guides", os: ["web"], desc: "Guias de investigação e técnicas de jornalismo investigativo de elite.", install: { web: "Acesse via Navegador." }, repo: "https://www.bellingcat.com/resources/2021/11/09/the-intelligence-high-way-a-guide-to-osint-on-the-world-wide-web/" },
        { name: "SANS OSINT", os: ["web"], desc: "Cursos e recursos profissionais de treinamento em OSINT do SANS Institute.", install: { web: "Acesse via Navegador." }, repo: "https://www.sans.org/cyber-security-courses/open-source-intelligence-gathering-analysis/" },
        { name: "IntelTechniques", os: ["web"], desc: "Recursos e podcasts do especialista Michael Bazzell sobre privacidade e OSINT.", install: { web: "Acesse via Navegador." }, repo: "https://inteltechniques.com" }
    ],
    NICHO: [
        { name: "Public Data (GitHub)", os: ["web"], desc: "Lista curada de datasets públicos focados em OSINT e inteligência.", install: { web: "Acesse via Navegador." }, repo: "https://github.com/awesomedata/awesome-public-datasets" },
        { name: "OSINT Techniques", os: ["web"], desc: "Blog e repositório de técnicas de investigação em setores de nicho.", install: { web: "Acesse via Navegador." }, repo: "https://osintcurio.us" },
        { name: "HateBase", os: ["web"], desc: "O maior repositório mundial de discurso de ódio online (investigação de grupos).", install: { web: "Acesse via Navegador." }, repo: "https://hatebase.org" }
    ],
    PHISHING: [
        { name: "Gophish", os: ["win", "lin"], desc: "Plataforma open source para simulações massivas de phishing.", install: { lin: "Baixe o binário e execute `./gophish`.", win: "Baixe o .exe oficial.", termux: "Não suportado." }, repo: "https://github.com/gophish/gophish" },
        { name: "Evilginx2", os: ["win", "lin"], desc: "Framework de phishing avançado que captura tokens de sessão e ignora MFA.", install: { lin: "go install github.com/kgretzky/evilginx2@latest", win: "Compile com Go no Windows.", termux: "Não suportado." }, repo: "https://github.com/kgretzky/evilginx2" },
        { name: "Phishing Database", os: ["win", "lin", "termux"], desc: "Repositorio de URLs e domínios de phishing ativos para bloqueio e análise.", install: { lin: "git clone", win: "Acesse via GitHub.", termux: "git clone" }, repo: "https://github.com/mitchellkrogza/Phishing.Database" },
        { name: "Zphisher", os: ["win", "lin", "termux"], desc: "Ferramenta de phishing automatizada e fácil de usar com 30+ templates.", install: { lin: "git clone https://github.com/htr-tech/zphisher && cd zphisher && bash zphisher.sh", win: "Execute via WSL.", termux: "pkg install git bash && git clone https://github.com/htr-tech/zphisher && bash zphisher.sh" }, repo: "https://github.com/htr-tech/zphisher" }
    ],
    DARKWEB: [
        { name: "Tor Browser", os: ["win", "lin"], desc: "Navegador focado em privacidade para acessar a rede .onion.", install: { lin: "Baixe o pacote no site oficial.", win: "Instalador .exe oficial.", termux: "Instale via Orbot." }, repo: "https://www.torproject.org" },
        { name: "OnionSearch", os: ["win", "lin", "termux"], desc: "Script para buscar termos em múltiplos motores de busca da Dark Web.", install: { lin: "pip install onionsearch", win: "pip install onionsearch", termux: "pip install onionsearch" }, repo: "https://github.com/megadose/onionsearch" },
        { name: "Ahmia.fi", os: ["web"], desc: "Motor de busca público para serviços ocultos na rede Tor.", install: { web: "Acesse via Navegador." }, repo: "https://ahmia.fi" },
        { name: "Torch", os: ["web"], desc: "Um dos motores de busca mais antigos e populares da Dark Web.", install: { web: "Acesse via Navegador." }, repo: "http://xmh57jrknzkhv6y3ls3ubv6iwixcebc2szhps6idbalm7v7ghv67fglad.onion/" }
    ],
    DATA_ANALYSIS: [
        { name: "Visallo", os: ["win", "lin"], desc: "Plataforma avançada para análise visual e descoberta em grandes volumes de dados.", install: { lin: "docker-compose up (requer hardware robusto).", win: "Docker Desktop.", termux: "N/A" }, repo: "https://github.com/visallo/visallo" }
    ],
    PRIVACY: [
        { name: "PrivacyTools", os: ["web"], desc: "O guia definitivo para software e hardware focado em privacidade e segurança.", install: { web: "Acesse via Navegador." }, repo: "https://www.privacytools.io" },
        { name: "Tails OS", os: ["win", "lin"], desc: "Sistema operacional live focado em amnésia total e privacidade via Tor.", install: { lin: "Grave em um pendrive.", win: "Grave em um pendrive.", termux: "N/A" }, repo: "https://tails.boum.org" },
        { name: "Veracrypt", os: ["win", "lin"], desc: "Software de criptografia de disco open source e extremamente seguro.", install: { lin: "sudo apt install veracrypt", win: "Instalador oficial.", termux: "Não suportado." }, repo: "https://www.veracrypt.fr" },
        { name: "DuckDuckGo", os: ["web"], desc: "Motor de busca que não rastreia usuários e bloqueia rastreadores.", install: { web: "Acesse via Navegador." }, repo: "https://duckduckgo.com" }
    ],
    SOCIAL: [
        { name: "Maigret", os: ["win", "lin", "termux"], desc: "Análise de perfis por username em 2500+ sites.", install: { lin: "pip install maigret", win: "pip install maigret", termux: "pip install maigret" }, repo: "https://github.com/soxoj/maigret" },
        { name: "WhatsMyName", os: ["win", "lin", "termux"], desc: "Busca de usernames em múltiplas plataformas.", install: { lin: "git clone https://github.com/WebBreacher/WhatsMyName.git", win: "Clone o repositório.", termux: "git clone" }, repo: "https://github.com/WebBreacher/WhatsMyName" },
        { name: "Social Analyzer", os: ["win", "lin", "termux"], desc: "Análise de perfis em redes sociais via API.", install: { lin: "pip install social-analyzer", win: "pip install social-analyzer", termux: "pip install social-analyzer" }, repo: "https://github.com/qeeqbox/social-analyzer" },
        { name: "Instaloader", os: ["win", "lin", "termux"], desc: "Download de dados e perfis do Instagram.", install: { lin: "pip install instaloader", win: "pip install instaloader", termux: "pip install instaloader" }, repo: "https://github.com/instaloader/instaloader" },
        { name: "Osintgram", os: ["win", "lin", "termux"], desc: "Ferramenta OSINT exclusiva para Instagram.", install: { lin: "git clone https://github.com/Datalux/Osintgram.git && pip install -r requirements.txt", win: "Clone e instale via pip.", termux: "pip install osintgram" }, repo: "https://github.com/Datalux/Osintgram" },
        { name: "Twint", os: ["win", "lin", "termux"], desc: "Scraping avançado do Twitter/X sem API key.", install: { lin: "pip3 install twint", win: "pip3 install twint", termux: "pip3 install twint" }, repo: "https://github.com/twintproject/twint" }
    ],
    IMAGENS: [
        { name: "TinEye", os: ["web"], desc: "Busca reversa de imagens líder mundial.", install: { web: "Acesse via Navegador." }, repo: "https://tineye.com" },
        { name: "PimEyes", os: ["web"], desc: "Busca facial por reconhecimento em milhões de imagens.", install: { web: "Acesse via Navegador." }, repo: "https://pimeyes.com" },
        { name: "Facecheck.id", os: ["web"], desc: "Busca facial online avançada.", install: { web: "Acesse via Navegador." }, repo: "https://facecheck.id" },
        { name: "Forensically", os: ["web"], desc: "Análise forense de imagens no navegador.", install: { web: "Acesse via Navegador." }, repo: "https://29a.ch/photo-forensics" }
    ],
    DEV: [
        { name: "GitHub Search", os: ["win", "lin", "termux"], desc: "Pesquisa avançada em código, repositórios e usuários do GitHub.", install: { lin: "Acesse via navegador ou CLI oficial.", win: "Acesse via navegador.", termux: "pkg install gh" }, repo: "https://github.com/search" },
        { name: "Stack Overflow", os: ["web"], desc: "Maior comunidade de desenvolvedores para busca de soluções técnicas.", install: { web: "Acesse via Navegador." }, repo: "https://stackoverflow.com" },
        { name: "Gitee", os: ["web"], desc: "Plataforma de hospedagem de código líder na China (alternativa ao GitHub).", install: { web: "Acesse via Navegador." }, repo: "https://gitee.com" }
    ],
    MOBILE: [
        { name: "App Annie", os: ["web"], desc: "Dados de mercado e inteligência sobre aplicativos móveis (focado em empresas).", install: { web: "Acesse via Navegador." }, repo: "https://www.data.ai" },
        { name: "APKMirror", os: ["web"], desc: "Repositório seguro para download de arquivos APK de aplicativos Android.", install: { web: "Acesse via Navegador." }, repo: "https://www.apkmirror.com" }
    ],
    GAMING: [
        { name: "SteamId.io", os: ["web"], desc: "Ferramenta para converter IDs da Steam e visualizar perfis detalhados.", install: { web: "Acesse via Navegador." }, repo: "https://steamid.io" },
        { name: "Twitch Insights", os: ["web"], desc: "Ferramenta de análise de streamers e visualização de chats em tempo real.", install: { web: "Acesse via Navegador." }, repo: "https://twitchinsights.net" },
        { name: "Discord Search", os: ["web"], desc: "Motores de busca específicos para servidores e convites de Discord.", install: { web: "Acesse via Navegador." }, repo: "https://disboard.org" }
    ],
    IMOVEIS: [
        { name: "Zillow", os: ["web"], desc: "Plataforma líder de registros imobiliários e histórico de vendas (EUA).", install: { web: "Acesse via Navegador." }, repo: "https://www.zillow.com" },
        { name: "Zap Imóveis", os: ["web"], desc: "Maior portal de imóveis do Brasil para pesquisa de mercado e registros.", install: { web: "Acesse via Navegador." }, repo: "https://www.zapimoveis.com.br" },
        { name: "GeoSampa", os: ["web"], desc: "Mapa digital oficial de SP com dados detalhados de imóveis e zonas.", install: { web: "Acesse via Navegador." }, repo: "https://geosampa.prefeitura.sp.gov.br" }
    ],
    LEGAL: [
        { name: "Jusbrasil", os: ["web"], desc: "O maior portal de informações jurídicas do Brasil, incluindo processos e leis.", install: { web: "Acesse via Navegador." }, repo: "https://www.jusbrasil.com.br" },
        { name: "CourtListener", os: ["web"], desc: "Acesso gratuito a registros judiciais, opiniões e processos (EUA).", install: { web: "Acesse via Navegador." }, repo: "https://www.courtlistener.com" },
        { name: "PACER", os: ["win", "lin", "termux"], desc: "Sistema oficial de acesso eletrônico aos registros judiciais federais dos EUA.", install: { lin: "Requer conta e navegador oficial.", win: "Browser oficial.", termux: "Browser oficial." }, repo: "https://pacer.uscourts.gov" }
    ],
    ACADEMICO: [
        { name: "Google Scholar", os: ["web"], desc: "Pesquisa acadêmica em artigos, teses e literatura técnica.", install: { web: "Acesse via Navegador." }, repo: "https://scholar.google.com" },
        { name: "ResearchGate", os: ["web"], desc: "Rede social para cientistas e pesquisadores compartilharem publicações.", install: { web: "Acesse via Navegador." }, repo: "https://www.researchgate.net" },
        { name: "Sci-Hub", os: ["web"], desc: "Repositório polêmico que fornece acesso gratuito a milhões de artigos pagos.", install: { web: "Acesse via Navegador." }, repo: "https://sci-hub.se" }
    ],
    SAUDE: [
        { name: "PubMed", os: ["web"], desc: "Base de dados gratuita de literatura biomédica e de saúde.", install: { web: "Acesse via Navegador." }, repo: "https://pubmed.ncbi.nlm.nih.gov" },
        { name: "CNES (Brasil)", os: ["web"], desc: "Cadastro Nacional de Estabelecimentos de Saúde para consulta oficial.", install: { web: "Acesse via Navegador." }, repo: "http://cnes.datasus.gov.br" }
    ],
    ART: [
        { name: "ArtStation", os: ["web"], desc: "Showcase de artistas profissionais em diversas áreas visuais.", install: { web: "Acesse via Navegador." }, repo: "https://www.artstation.com" },
        { name: "Behance", os: ["web"], desc: "Plataforma de rede social para mostrar e descobrir trabalhos criativos.", install: { web: "Acesse via Navegador." }, repo: "https://www.behance.net" }
    ],
    MUSIC: [
        { name: "SoundCloud Search", os: ["web"], desc: "Busca de faixas de áudio, podcasts e perfis de artistas independentes.", install: { web: "Acesse via Navegador." }, repo: "https://soundcloud.com" },
        { name: "Discogs", os: ["web"], desc: "Base de dados massiva de lançamentos musicais e discografias.", install: { web: "Acesse via Navegador." }, repo: "https://www.discogs.com" }
    ],
    COMMERCE: [
        { name: "Alibaba", os: ["web"], desc: "Investigação de fornecedores e comércio internacional B2B.", install: { web: "Acesse via Navegador." }, repo: "https://www.alibaba.com" },
        { name: "Amazon Search", os: ["web"], desc: "Análise de produtos, vendedores e reviews globais.", install: { web: "Acesse via Navegador." }, repo: "https://www.amazon.com" }
    ],
    EMERGENCY: [
        { name: "LiveATC.net", os: ["web"], desc: "Transmissão ao vivo de áudio de comunicações de controle de tráfego aéreo.", install: { web: "Acesse via Navegador." }, repo: "https://www.liveatc.net" },
        { name: "Broadcastify", os: ["web"], desc: "A maior fonte mundial de transmissões de áudio de segurança pública (polícia, bombeiros).", install: { web: "Acesse via Navegador." }, repo: "https://www.broadcastify.com" },
        { name: "IncidentShare", os: ["win", "lin"], desc: "Plataforma de compartilhamento de vídeo e dados para gerenciamento de incidentes.", install: { lin: "Acesse via plataforma web.", win: "Acesse via plataforma web.", termux: "Não suportado." }, repo: "https://incidentshare.com" }
    ],
    LANGUAGES: [
        { name: "DeepL Translate", os: ["web"], desc: "O tradutor mais preciso do mundo, baseado em redes neurais de alta performance.", install: { web: "Acesse via Navegador." }, repo: "https://www.deepl.com" },
        { name: "Yandex Translate", os: ["web"], desc: "Ferramenta de tradução com excelente suporte para idiomas do Leste Europeu e Ásia.", install: { web: "Acesse via Navegador." }, repo: "https://translate.yandex.com" }
    ],
    NEWS: [
        { name: "Google News Archive", os: ["web"], desc: "Arquivo histórico de jornais digitalizados de todo o mundo.", install: { web: "Acesse via Navegador." }, repo: "https://news.google.com/newspapers" },
        { name: "NewsGuard", os: ["win", "lin", "termux"], desc: "Ferramenta que classifica a confiabilidade de sites de notícias para combater desinformação.", install: { lin: "Extensão para navegador.", win: "Extensão para navegador.", termux: "Não suportado." }, repo: "https://www.newsguardtech.com" }
    ],
    SCIENCE: [
        { name: "NASA Open Data", os: ["web"], desc: "Acesso a todos os conjuntos de dados públicos da NASA para pesquisa.", install: { web: "Acesse via Navegador." }, repo: "https://data.nasa.gov" },
        { name: "Dryad", os: ["web"], desc: "Repositório internacional aberto de dados de pesquisa científica.", install: { web: "Acesse via Navegador." }, repo: "https://datadryad.org" }
    ],
    GOVERNMENT: [
        { name: "GovTrack.us", os: ["web"], desc: "Rastreamento independente de membros do Congresso dos EUA e legislação.", install: { web: "Acesse via Navegador." }, repo: "https://www.govtrack.us" },
        { name: "Portal da Transparência (BR)", os: ["web"], desc: "Consulta oficial de gastos e dados do Governo Federal do Brasil.", install: { web: "Acesse via Navegador." }, repo: "http://www.portaltransparencia.gov.br" }
    ],
    INTL: [
        { name: "UN Data", os: ["web"], desc: "Base de dados estatísticos completa das Nações Unidas.", install: { web: "Acesse via Navegador." }, repo: "http://data.un.org" },
        { name: "World Bank Data", os: ["web"], desc: "Acesso livre a dados globais de desenvolvimento e economia.", install: { web: "Acesse via Navegador." }, repo: "https://data.worldbank.org" }
    ],
    CARTOGRAPHY: [
        { name: "Old Maps Online", os: ["web"], desc: "Portal para pesquisa e visualização de mapas históricos de bibliotecas globais.", install: { web: "Acesse via Navegador." }, repo: "https://www.oldmapsonline.org" },
        { name: "David Rumsey Map Collection", os: ["web"], desc: "Uma das maiores coleções digitais de mapas raros do mundo.", install: { web: "Acesse via Navegador." }, repo: "https://www.davidrumsey.com" }
    ],
    INDUSTRY: [
        { name: "Thomasnet", os: ["web"], desc: "Plataforma líder para descoberta de fornecedores industriais na América do Norte.", install: { web: "Acesse via Navegador." }, repo: "https://www.thomasnet.com" },
        { name: "Europages", os: ["web"], desc: "Diretório líder de empresas e fornecedores industriais na Europa.", install: { web: "Acesse via Navegador." }, repo: "https://www.europages.com" }
    ],
    PHARMA: [
        { name: "ClinicalTrials.gov", os: ["web"], desc: "Banco de dados de estudos clínicos financiados de forma pública e privada.", install: { web: "Acesse via Navegador." }, repo: "https://clinicaltrials.gov" },
        { name: "FDA Drug Database", os: ["web"], desc: "Informações oficiais sobre aprovação de medicamentos e segurança nos EUA.", install: { web: "Acesse via Navegador." }, repo: "https://www.accessdata.fda.gov/scripts/cder/daf/" }
    ],
    GRC: [
        { name: "eramba", os: ["win", "lin"], desc: "Software open source de GRC para gestão de riscos e compliance.", install: { lin: "Docker instance.", win: "Docker instance.", termux: "Não suportado." }, repo: "https://www.eramba.org" },
        { name: "SimpleRisk", os: ["win", "lin"], desc: "Ferramenta de gestão de riscos de segurança simples e eficaz.", install: { lin: "Instalação via web server (LAMP).", win: "Acesse via conta cloud ou self-host.", termux: "N/A" }, repo: "https://www.simplerisk.com" }
    ],
    IA_ML: [
        { name: "ChatGPT", os: ["web"], desc: "Análise e sumarização de dados complexos com IA.", install: { web: "Acesse via Navegador." }, repo: "https://chat.openai.com" },
        { name: "Ollama", os: ["win", "lin"], desc: "Execução local de modelos de linguagem (LLMs) para máxima privacidade.", install: { lin: "curl -fsSL https://ollama.com/install.sh | sh", win: "Baixe o instalador oficial Ollama.exe.", termux: "Não suportado diretamente." }, repo: "https://github.com/ollama/ollama" },
        { name: "YOGA", os: ["win", "lin"], desc: "Analisador gráfico OSINT para visualização de conexões complexas.", install: { lin: "pip install yoga-osint", win: "pip install yoga-osint", termux: "pip install yoga-osint" }, repo: "https://github.com/Screaming-Pillow/YOGA" }
    ],
    BLOCKCHAIN_ADV: [
        { name: "Arkham Intelligence", os: ["web"], desc: "De-anonimização de endereços de blockchain e análise de entidades.", install: { web: "Acesse via Navegador." }, repo: "https://www.arkhamintelligence.com" },
        { name: "Chainalysis Reactor", os: ["win", "lin"], desc: "Software de investigação criminal para rastreamento de criptoativos.", install: { lin: "Acesso corporativo via navegador.", win: "Acesso corporativo.", termux: "N/A" }, repo: "https://www.chainalysis.com" },
        { name: "MistTrack", os: ["web"], desc: "Ferramenta de rastreamento de criptomoedas focada em segurança e AML.", install: { web: "Acesse via Navegador." }, repo: "https://misttrack.io" },
        { name: "Blockchair", os: ["web"], desc: "Mecanismo de busca e análise multi-blockchain universal.", install: { web: "Acesse via Navegador." }, repo: "https://blockchair.com" }
    ],
    RADIO_SDR: [
        { name: "Flightradar24", os: ["web"], desc: "Rastreamento global de voos em tempo real via ADS-B.", install: { web: "Acesse via Navegador." }, repo: "https://www.flightradar24.com" },
        { name: "WebSDR", os: ["win", "lin", "termux"], desc: "Receptores de rádio definidos por software acessíveis via web.", install: { lin: "Acesse servidores globais via navegador.", win: "Acesse via navegador.", termux: "Acesse via navegador." }, repo: "http://www.websdr.org" },
        { name: "RadioReference", os: ["web"], desc: "A maior base de dados de frequências de rádio e comunicações do mundo.", install: { web: "Acesse via Navegador." }, repo: "https://www.radioreference.com" }
    ],
    SATELITE_GEO: [
        { name: "Google Earth Engine", os: ["web"], desc: "Plataforma de computação em nuvem para análise de dados geográficos.", install: { web: "Acesse via Navegador." }, repo: "https://earthengine.google.com" },
        { name: "Zoom Earth", os: ["web"], desc: "Mapas de satélite em tempo real, furacões e rastreamento de incêndios.", install: { web: "Acesse via Navegador." }, repo: "https://zoom.earth" },
        { name: "SkyTruth", os: ["web"], desc: "Monitoramento ambiental via satélite para detectar poluição e pesca ilegal.", install: { web: "Acesse via Navegador." }, repo: "https://skytruth.org" }
    ],
    DARKWEB_SPEC: [
        { name: "Ahmia", os: ["web"], desc: "Motor de busca para serviços ocultos na rede Tor.", install: { web: "Acesse via Navegador." }, repo: "https://ahmia.fi" },
        { name: "DarkSearch", os: ["web"], desc: "O primeiro motor de busca real da Dark Web com indexação em tempo real.", install: { web: "Acesse via Navegador." }, repo: "https://darksearch.io" },
        { name: "OnionScan", os: ["win", "lin"], desc: "Ferramenta para investigar a segurança de serviços ocultos onion.", install: { lin: "go get github.com/s-rah/onionscan", win: "Compile com Go.", termux: "pkg install golang && go get ..." }, repo: "https://github.com/s-rah/onionscan" },
        { name: "TorBot", os: ["win", "lin"], desc: "Crawler de dark web para coletar informações de domínios .onion.", install: { lin: "git clone e instale requisitos python.", win: "Use via WSL.", termux: "Requer dependências complexas." }, repo: "https://github.com/DedSecInside/TorBot" }
    ],
    DEV_AUTOMATION: [
        { name: "Playwright", os: ["win", "lin"], desc: "Automação de navegador moderna, confiável e rápida para scraping.", install: { lin: "npm install playwright", win: "npm install playwright", termux: "Não suportado." }, repo: "https://playwright.dev" },
        { name: "Scrapy", os: ["win", "lin", "termux"], desc: "Framework de web scraping rápido e poderoso para Python.", install: { lin: "pip install scrapy", win: "pip install scrapy", termux: "pip install scrapy" }, repo: "https://scrapy.org" },
        { name: "Requests-HTML", os: ["win", "lin", "termux"], desc: "Scraping de HTML para humanos (com suporte a JavaScript).", install: { lin: "pip install requests-html", win: "pip install requests-html", termux: "pip install requests-html" }, repo: "https://github.com/psf/requests-html" }
    ],
    DATA_VIS_NET: [
        { name: "Gephi", os: ["win", "lin"], desc: "Plataforma líder para visualização e exploração de todos os tipos de redes.", install: { lin: "Baixe o binário oficial.", win: "Use o instalador .exe.", termux: "Não suportado." }, repo: "https://gephi.org" },
        { name: "Graphistry", os: ["web"], desc: "Análise visual de grafos em escala acelerada por GPU.", install: { web: "Acesse via Navegador." }, repo: "https://www.graphistry.com" },
        { name: "Sigma.js", os: ["win", "lin"], desc: "Biblioteca JavaScript dedicada à visualização de grafos na web.", install: { lin: "npm install sigma", win: "npm install sigma", termux: "npm install sigma" }, repo: "http://sigmajs.org" }
    ],
    LEAKS_DB: [
        { name: "DeHashed", os: ["web"], desc: "Ferramenta de busca de ativos e vazamentos para análise de segurança.", install: { web: "Acesse via Navegador." }, repo: "https://www.dehashed.com" },
        { name: "Intelligence X", os: ["web"], desc: "Motor de busca que indexa darknet, vazamentos e dados históricos.", install: { web: "Acesse via Navegador." }, repo: "https://intelx.io" },
        { name: "Leak-Lookup", os: ["web"], desc: "Pesquisa em milhares de bancos de dados vazados para verificar dados.", install: { web: "Acesse via Navegador." }, repo: "https://leak-lookup.com" }
    ],
    PHISHING_ADV: [
        { name: "Modlishka", os: ["win", "lin"], desc: "Proxy de phishing reverso potente para contornar autenticação multifator.", install: { lin: "go get -u github.com/drk3y/modlishka", win: "Compile com Go.", termux: "Compile com Go." }, repo: "https://github.com/drk3y/modlishka" }
    ],
    BLUE_TEAM_OSINT: [
        { name: "MISP", os: ["lin"], desc: "Plataforma de compartilhamento de informações sobre ameaças e malware.", install: { lin: "Instalação via script ou Docker.", win: "Use via Docker ou VM.", termux: "Não suportado." }, repo: "https://www.misp-project.org" },
        { name: "TheHive", os: ["lin"], desc: "Plataforma escalável para resposta a incidentes e análise forense.", install: { lin: "Instalação via pacotes .deb ou Docker.", win: "Use via Docker.", termux: "N/A" }, repo: "https://thehive-project.org" },
        { name: "Wazuh (XDR)", os: ["win", "lin"], desc: "Segurança de endpoints e monitoramento de conformidade baseado em SIEM.", install: { lin: "curl -sO https://packages.wazuh.com/...install.sh", win: "Instale o Wazuh Agent .msi.", termux: "N/A" }, repo: "https://wazuh.com" }
    ],
    SEARCH_DORKS: [
        { name: "Google Dorks", os: ["web"], desc: "Operadores de busca avançada para encontrar informações expostas no Google.", install: { web: "Acesse via Navegador." }, repo: "https://www.exploit-db.com/google-hacking-database" },
        { name: "Shodan Dorks", os: ["win", "lin", "termux"], desc: "Consultas especializadas para encontrar dispositivos conectados à internet.", install: { lin: "Acesse via Shodan UI ou CLI.", win: "Acesse via CLI (Python).", termux: "pip install shodan" }, repo: "https://www.shodan.io" },
        { name: "GitHub Dorks", os: ["web"], desc: "Pesquisas para encontrar segredos, chaves e dados sensíveis em repositórios de código.", install: { web: "Acesse via Navegador." }, repo: "https://github.com/techgaun/github-dorks" }
    ],
    MOBILE_ADV: [
        { name: "APKTool", os: ["win", "lin", "termux"], desc: "Ferramenta para engenharia reversa de arquivos APK de terceiros.", install: { lin: "sudo apt install apktool", win: "Baixe o wrapper script e o jar.", termux: "pkg install apktool" }, repo: "https://ibotpeaches.github.io/Apktool/" },
        { name: "JADX", os: ["win", "lin", "termux"], desc: "Decompilador de linha de comando e GUI para arquivos Dex e APK.", install: { lin: "sudo apt install jadx", win: "Baixe the release zip e execute o .bat.", termux: "pkg install jadx" }, repo: "https://github.com/skylot/jadx" }
    ],
    INFRA_NET: [
        { name: "BGPStream", os: ["web"], desc: "Monitoramento em tempo real de eventos globais de roteamento BGP.", install: { web: "Acesse via Navegador." }, repo: "https://bgpstream.com" },
        { name: "PeeringDB", os: ["web"], desc: "Base de dados centralizada para informações de peering e interconexão.", install: { web: "Acesse via Navegador." }, repo: "https://www.peeringdb.com" },
        { name: "RIPE Stat", os: ["web"], desc: "Interface web que fornece tudo o que você precisa saber sobre recursos de internet.", install: { web: "Acesse via Navegador." }, repo: "https://stat.ripe.net" }
    ],
    GAMING_INTEL: [
        { name: "SteamID.uk", os: ["web"], desc: "Ferramenta de busca e análise de perfis da plataforma Steam.", install: { web: "Acesse via Navegador." }, repo: "https://steamid.uk" },
        { name: "Tracker.gg", os: ["web"], desc: "Rede de rastreamento de estatísticas para os jogos competitivos mais populares.", install: { web: "Acesse via Navegador." }, repo: "https://tracker.gg" },
        { name: "VacBan", os: ["web"], desc: "Verificação de banimentos em tempo real para contas Steam e jogos Valve.", install: { web: "Acesse via Navegador." }, repo: "https://vacban.com" }
    ],
    COMPLIANCE_LEGAL: [
        { name: "GDPR.eu", os: ["web"], desc: "Portal oficial de recursos e conformidade com o Regulamento Geral de Proteção de Dados.", install: { web: "Acesse via Navegador." }, repo: "https://gdpr.eu" },
        { name: "MuckRock (FOIA)", os: ["web"], desc: "Plataforma para facilitar pedidos de Lei de Acesso à Informação.", install: { web: "Acesse via Navegador." }, repo: "https://www.muckrock.com" },
        { name: "Privacy International", os: ["web"], desc: "Organização que monitora tecnologias de vigilância e defende a privacidade global.", install: { web: "Acesse via Navegador." }, repo: "https://privacyinternational.org" }
    ],
    BIO_GENEALOGIA: [
        { name: "GEDmatch", os: ["web"], desc: "Ferramentas para comparação de DNA e pesquisa genealógica.", install: { web: "Acesse via Navegador." }, repo: "https://www.gedmatch.com" },
        { name: "Ancestry", os: ["web"], desc: "O maior recurso do mundo para história familiar e genealogia genética.", install: { web: "Acesse via Navegador." }, repo: "https://www.ancestry.com" },
        { name: "FamilyTreeDNA", os: ["web"], desc: "Testes e ferramentas de DNA para pesquisa de ancestralidade e linhagem.", install: { web: "Acesse via Navegador." }, repo: "https://www.familytreedna.com" }
    ],
    DESIGN_PATENTS: [
        { name: "Google Patents", os: ["web"], desc: "Buscador abrangente de milhões de patentes de todo o mundo.", install: { web: "Acesse via Navegador." }, repo: "https://patents.google.com" },
        { name: "USPTO Search", os: ["web"], desc: "Base de dados oficial de patentes e marcas registradas dos EUA.", install: { web: "Acesse via Navegador." }, repo: "https://www.uspto.gov" },
    ],
    MUSIC_AUDIO_ADV: [
        { name: "Shazam", os: ["win", "lin", "termux"], desc: "Identificação instantânea de qualquer música tocando ao redor.", install: { lin: "Acesse via app mobile.", win: "Incluso via Windows/Browser.", termux: "Acesse via app." }, repo: "https://www.shazam.com" },
        { name: "MusicBrainz", os: ["web"], desc: "Enciclopédia musical aberta que coleta metadados de música e os disponibiliza.", install: { web: "Acesse via Navegador." }, repo: "https://musicbrainz.org" },
    ],
    FOOD_SERVICE: [
        { name: "Yelp", os: ["web"], desc: "Avaliações e recomendações de estabelecimentos locais e restaurantes.", install: { web: "Acesse via Navegador." }, repo: "https://www.yelp.com" },
        { name: "OpenTable", os: ["web"], desc: "Portal global para reservas de restaurantes e gestão de experiências.", install: { web: "Acesse via Navegador." }, repo: "https://www.opentable.com" },
        { name: "Zomato", os: ["web"], desc: "Guia abrangente de restaurantes e serviços de entrega global.", install: { web: "Acesse via Navegador." }, repo: "https://www.zomato.com" }
    ],
    EMERGENCY_GLOBAL: [
        { name: "PulsePoint", os: ["web"], desc: "Alertas de emergência e localização de desfibriladores (AED) em tempo real.", install: { web: "Acesse via Navegador." }, repo: "https://www.pulsepoint.org" },
        { name: "Citizen", os: ["web"], desc: "Notificações de segurança em tempo real e incidentes ao vivo perto de você.", install: { web: "Acesse via Navegador." }, repo: "https://citizen.com" },
        { name: "FEMA Mobile", os: ["web"], desc: "Alertas de desastres naturais e preparação para emergências nos EUA.", install: { web: "Acesse via Navegador." }, repo: "https://www.fema.gov/about/news-multimedia/mobile-products" }
    ],
    ENVIRONMENT_OSINT: [
        { name: "Global Forest Watch", os: ["web"], desc: "Monitoramento de florestas em tempo real via satélite e IA.", install: { web: "Acesse via Navegador." }, repo: "https://www.globalforestwatch.org" },
        { name: "Global Fishing Watch", os: ["web"], desc: "Rastreamento de frotas pesqueiras globais para combater a pesca ilegal.", install: { web: "Acesse via Navegador." }, repo: "https://globalfishingwatch.org" },
        { name: "Windy", os: ["web"], desc: "Visualização interativa de modelos meteorológicos e dados ambientais.", install: { web: "Acesse via Navegador." }, repo: "https://www.windy.com" }
    ],
    EDUCATION_ADV: [
        { name: "Coursera", os: ["web"], desc: "Acesso a cursos de alta qualidade de universidades e empresas globais.", install: { web: "Acesse via Navegador." }, repo: "https://www.coursera.org" },
        { name: "Project Gutenberg", os: ["web"], desc: "Biblioteca de mais de 60.000 e-books gratuitos de domínio público.", install: { web: "Acesse via Navegador." }, repo: "https://www.gutenberg.org" },
        { name: "Khan Academy", os: ["web"], desc: "Recursos de aprendizagem gratuitos e personalizados para todas as idades.", install: { web: "Acesse via Navegador." }, repo: "https://www.khanacademy.org" }
    ],
    HEALTH_MEDICAL: [
        { name: "HealthMap", os: ["web"], desc: "Monitoramento global de surtos de doenças e alertas de saúde pública.", install: { web: "Acesse via Navegador." }, repo: "https://healthmap.org" }
    ],
    LAW_LEGISLATION: [
        { name: "EUR-Lex", os: ["web"], desc: "Acesso oficial e gratuito ao direito da União Europeia.", install: { web: "Acesse via Navegador." }, repo: "https://eur-lex.europa.eu" }
    ],
    ECOMMERCE_MARKET: [
        { name: "Mercado Livre", os: ["web"], desc: "O maior marketplace e ecossistema de e-commerce da América Latina.", install: { web: "Acesse via Navegador." }, repo: "https://www.mercadolivre.com.br" },
        { name: "AliExpress", os: ["web"], desc: "Plataforma global de varejo especializada em exportação chinesa.", install: { web: "Acesse via Navegador." }, repo: "https://www.aliexpress.com" }
    ],
    VEHICLES_TRANS_ADV: [
        { name: "FlightAware", os: ["web"], desc: "Dados abrangentes de tráfego aéreo e rastreamento de voos global.", install: { web: "Acesse via Navegador." }, repo: "https://flightaware.com" },
        { name: "Carfax", os: ["web"], desc: "Relatórios detalhados de histórico de veículos (especialmente EUA/Canadá).", install: { web: "Acesse via Navegador." }, repo: "https://www.carfax.com" }
    ],
    COMMUNITIES_INTEL: [
        { name: "Reddit (r/OSINT)", os: ["web"], desc: "Comunidade ativa de profissionais e entusiastas de inteligência de fontes abertas.", install: { web: "Acesse via Navegador." }, repo: "https://www.reddit.com/r/OSINT/" },
        { name: "OSINT Curious Discord", os: ["win", "lin", "termux"], desc: "Plataforma de colaboração em tempo real para aprendizado de técnicas OSINT.", install: { lin: "Acesse via Navegador ou Client.", win: "Use via Discord App.", termux: "Use via Discord App." }, repo: "https://osintcurio.us" }
    ],
    TRAINING_CTF: [
        { name: "HackTheBox", os: ["web"], desc: "Plataforma de treinamento em segurança cibernética massiva e competitiva.", install: { web: "Acesse via Navegador." }, repo: "https://www.hackthebox.com" },
        { name: "Trace Labs", os: ["web"], desc: "CTF focado em OSINT para ajudar na busca de pessoas desaparecidas no mundo real.", install: { web: "Acesse via Navegador." }, repo: "https://www.tracelabs.org" }
    ],
    PODCASTS_YT: [
        { name: "IntelTechniques Podcast", os: ["web"], desc: "O show definitivo sobre privacidade, segurança e OSINT por Michael Bazzell.", install: { web: "Acesse via Navegador." }, repo: "https://inteltechniques.com/podcast.html" },
        { name: "Bellingcat Shorts", os: ["web"], desc: "Tutoriais rápidos e investigações visuais de impacto no YouTube.", install: { web: "Acesse via Navegador." }, repo: "https://www.youtube.com/@bellingcat" }
    ],
    NEWSLETTERS_BLOGS: [
        { name: "Sector035 (Week in OSINT)", os: ["web"], desc: "A newsletter semanal mais respeitada do mundo OSINT.", install: { web: "Acesse via Navegador." }, repo: "https://linktr.ee/sector035" },
        { name: "Bellingcat Blog", os: ["web"], desc: "Artigos e guias detalhados sobre as investigações digitais mais famosas do mundo.", install: { web: "Acesse via Navegador." }, repo: "https://www.bellingcat.com" }
    ]
};

const backgroundLogs = [
    "Estabelecendo túnel criptografado via rede Tor...",
    "Ignorando inspeção profunda de pacotes (DPI)...",
    "Interceptando handshakes de autenticação...",
    "Enviando shadow_crawler.py para nó remoto...",
    "Limpando rastros de logs de autenticação...",
    "Sincronizando com botnets escravas [152 ativas]...",
    "Recuperando variáveis de ambiente secretas...",
    "Aviso: Nível de entropia caindo. Mascarando sessão...",
    "Acesso Shadow persistente. Comando: /exec_all"
];

let currentTool = null;

function addLog(msg, type = "SHADOW_LOG") {
    const logBox = document.getElementById('log-stream');
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = 'log-line';
    const localizedType = type === 'USER_ACTION' ? 'AÇÃO_USUÁRIO' : 'LOG_SISTEMA';
    line.innerHTML = `[${time}] <span class="${type === 'USER_ACTION' ? 'glow-green' : ''}">${localizedType}:</span> ${msg}`;

    logBox.appendChild(line);
    if (logBox.childNodes.length > 8) logBox.removeChild(logBox.firstChild);
    logBox.scrollTop = logBox.scrollHeight;
}

function getOSBadges(osArray) {
    if (!osArray) return '';
    return osArray.map(os => {
        const name = os === 'win' ? 'WINDOWS' : os === 'lin' ? 'LINUX' : os === 'web' ? 'WEB' : 'TERMUX';
        return `<span class="os-badge ${os}">${name}</span>`;
    }).join('');
}

function parseMarkdown(text) {
    if (!text) return '';
    // Parser ultra-limpo para estilo Terminal (PT-BR)
    // BLOQUEIO ESTRITO DE IMAGENS PRIMEIRO (antes de processar links)
    let html = text
        .replace(/<img[^>]*>/g, '')
        .replace(/<svg[^>]*>[\s\S]*?<\/svg>/g, '')
        .replace(/<p align="center">[\s\S]*?<\/p>/g, '')
        .replace(/<div align="center">[\s\S]*?<\/div>/g, '')
        .replace(/https?:\/\/[\S]+\.(png|jpg|jpeg|gif|webp|svg)/gi, '')
        .replace(/\[!\[([^\]]*)\]\(([^)]+)\)\]\(([^)]+)\)/g, '')
        .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '')
        // Títulos
        .replace(/^# (.*$)/gim, '<h1>>> $1</h1>')
        .replace(/^## (.*$)/gim, '<h2>>> $1</h2>')
        .replace(/^### (.*$)/gim, '<h3>>> $1</h3>')
        // Listas
        .replace(/^\* (.*$)/gim, '<li>- $1</li>')
        .replace(/^- (.*$)/gim, '<li>- $1</li>')
        // Código
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        // Links (apenas visual)
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<span class="link">$1</span>');

    return html;
}

async function fetchReadme(repoUrl) {
    const readmeBox = document.getElementById('modal-tool-readme');

    // Se não for GitHub, não tente baixar README
    if (!repoUrl.includes('github.com')) {
        return `>> FONTE_EXTERNA: Este recurso não está no GitHub.\n>> Acesse diretamente: ${repoUrl}\n>> Tipo: Site Oficial / Plataforma Web`;
    }

    readmeBox.innerHTML = `<div class="blink">SINCRONIZANDO_DOCUMENTAÇÃO (GITHUB)...</div>`;

    const rawBase = repoUrl.replace('github.com', 'raw.githubusercontent.com');
    const branches = ['master', 'main', 'develop'];

    for (const branch of branches) {
        try {
            const url = `${rawBase}/${branch}/README.md`;
            const response = await fetch(url);
            if (response.ok) {
                const text = await response.text();
                return text.substring(0, 5000);
            }
        } catch (e) { }
    }
    return ">> ERRO_SISTEMA: DOCUMENTAÇÃO_NÃO_ENCONTRADA_OU_ACESSO_NEGADO";
}

function updateInstallGuide(os) {
    const installBox = document.getElementById('modal-tool-install');
    const tabs = document.querySelectorAll('.os-tab');

    tabs.forEach(t => {
        t.classList.remove('active');
        if (t.dataset.os === os) t.classList.add('active');
    });

    if (currentTool && currentTool.install) {
        const cmd = currentTool.install[os] || ">> SISTEMA_INCOMPATÍVEL: COMANDO_NÃO_DISPONÍVEL";
        installBox.textContent = cmd;
    }
    addLog(`Alterado alvo de instalação para ${os.toUpperCase()}`, "USER_ACTION");
}

async function showDetails(cat, toolName) {
    const tool = cyberTools[cat].find(t => t.name === toolName);
    if (!tool) return;
    currentTool = tool;

    addLog(`Acessando base de dados: ${toolName}`, "USER_ACTION");

    const modal = document.getElementById('tool-modal');
    document.getElementById('modal-tool-name').textContent = `> ${tool.name.toUpperCase()}_DETALHES`;
    document.getElementById('modal-tool-desc').textContent = tool.desc;
    document.getElementById('modal-tool-os').innerHTML = getOSBadges(tool.os);

    const repoBtn = document.getElementById('btn-repo-link');
    repoBtn.href = tool.repo;
    repoBtn.textContent = tool.repo.includes('github.com') ? 'ABRIR_REPOSITÓRIO' : 'SITE_OFICIAL';

    const defaultOs = tool.os.includes('web') ? 'web' : 'lin';
    updateInstallGuide(defaultOs);

    modal.style.display = 'flex';

    const readmeBox = document.getElementById('modal-tool-readme');
    readmeBox.scrollTop = 0;

    const rawReadme = await fetchReadme(tool.repo);
    readmeBox.innerHTML = parseMarkdown(rawReadme);
    addLog(`Sincronização de buffer completa para ${toolName}`, "SHADOW_LOG");
}

function renderTools(cat) {
    addLog(`Alternando para setor: ${cat}`, "USER_ACTION");
    const list = document.getElementById('tool-list');
    const title = document.getElementById('current-cat-title');
    title.textContent = `> FERRAMENTAS: ${cat}`;

    const escapeName = (name) => name.replace(/'/g, "\\'").replace(/"/g, '&quot;');

    list.innerHTML = cyberTools[cat].map(tool => `
        <div class="tool-item" onclick="showDetails('${cat}', '${escapeName(tool.name)}')">
            <h3>${tool.name}</h3>
            <div class="os-badges small">${getOSBadges(tool.os)}</div>
            <p>${tool.desc}</p>
        </div>
    `).join('');
}

function streamBackgroundLogs() {
    setInterval(() => {
        const msg = backgroundLogs[Math.floor(Math.random() * backgroundLogs.length)];
        addLog(msg, "SHADOW_LOG");
    }, 5000);
}

document.addEventListener('DOMContentLoaded', () => {
    renderTools('OFFENSIVE');
    streamBackgroundLogs();

    const navBtns = document.querySelectorAll('.cat-btn');
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            navBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderTools(btn.dataset.cat);
        });
    });

    const osTabs = document.querySelectorAll('.os-tab');
    osTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            updateInstallGuide(tab.dataset.os);
        });
    });

    document.getElementById('btn-close-tool').addEventListener('click', () => {
        addLog("Terminal de detalhes fechado.", "USER_ACTION");
        document.getElementById('tool-modal').style.display = 'none';
        currentTool = null;
    });

    setupSearch();
    setupShell();
    setupThemes();
});

function setupSearch() {
    const searchInput = document.getElementById('tool-search');
    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        if (!query) {
            const activeBtn = document.querySelector('.cat-btn.active');
            renderTools(activeBtn.dataset.cat);
            return;
        }

        const list = document.getElementById('tool-list');
        const title = document.getElementById('current-cat-title');
        title.textContent = `> RESULTADOS: "${query.toUpperCase()}"`;

        let results = [];
        Object.keys(cyberTools).forEach(cat => {
            const found = cyberTools[cat].filter(t =>
                t.name.toLowerCase().includes(query) ||
                t.desc.toLowerCase().includes(query)
            ).map(t => ({ ...t, category: cat }));
            results = [...results, ...found];
        });

        const escapeName = (name) => name.replace(/'/g, "\\'").replace(/"/g, '&quot;');

        list.innerHTML = results.map(tool => `
            <div class="tool-item" onclick="showDetails('${tool.category}', '${escapeName(tool.name)}')">
                <h3>${tool.name} <small style="font-size: 0.6rem; opacity: 0.5;">[${tool.category}]</small></h3>
                <div class="os-badges small">${getOSBadges(tool.os)}</div>
                <p>${tool.desc}</p>
            </div>
        `).join('') || '<div class="log-line">>> NENHUM_RESULTADO_ENCONTRADO</div>';
    });
}


function setupShell() {
    const shellInput = document.getElementById('shell-input');
    shellInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const cmd = shellInput.value.trim().toLowerCase();
            shellInput.value = '';
            processCommand(cmd);
        }
    });

    function processCommand(cmd) {
        addLog(`shell: ${cmd}`, "USER_ACTION");
        if (cmd === 'help') {
            addLog("COMANDOS: help, cls, scan, exploit, status, whoami", "SHADOW_LOG");
        } else if (cmd === 'cls' || cmd === 'clear') {
            document.getElementById('log-stream').innerHTML = '';
            addLog("Buffer de logs limpo.", "SHADOW_LOG");
        } else if (cmd === 'scan') {
            addLog("Iniciando varredura profunda de rede...", "SHADOW_LOG");
            setTimeout(() => addLog("3 alvos encontrados em 192.168.1.0/24", "SHADOW_LOG"), 1000);
        } else if (cmd === 'whoami') {
            addLog("shadow_crawler // root_access_level_9", "SHADOW_LOG");
        } else if (cmd === 'exploit') {
            addLog("Erro: Nenhuma vulnerabilidade selecionada. Use 'scan' primeiro.", "SHADOW_LOG");
        } else if (cmd === 'status') {
            addLog(`SISTEMA: OK | FERRAMENTAS: ${Object.keys(cyberTools).length} CATEGORIAS`, "SHADOW_LOG");
        } else if (cmd !== '') {
            addLog(`Comando não reconhecido: ${cmd}`, "SHADOW_LOG");
        }
    }
}

function setupThemes() {
    const themeBtns = document.querySelectorAll('.theme-btn');
    themeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const theme = btn.dataset.theme;
            document.body.dataset.theme = theme;
            addLog(`Tema alterado para: ${theme.toUpperCase()}`, "USER_ACTION");
        });
    });
}
