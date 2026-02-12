import requests
from bs4 import BeautifulSoup
import database
import time
import telebot

# Mesma configuração do bot
API_TOKEN = 'SEU_TOKEN_AQUI'
CHAT_ID = 'SEU_CHAT_ID_AQUI' # O bot enviará para esse ID os alertas
bot = telebot.TeleBot(API_TOKEN)

def google_dork_scan(query):
    """
    Simula um Google Dork para buscar menções em sites de 'pastes'
    """
    results = []
    # Dorks úteis: site:pastebin.com "CONTEUDO", site:github.com "CONTEUDO", etc.
    dorks = [
        f'site:pastebin.com "{query}"',
        f'site:controlc.com "{query}"',
        f'site:github.com "{query}"',
        f'"{query}" leak'
    ]
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for dork in dorks:
        try:
            url = f"https://www.google.com/search?q={dork}"
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Busca links nos resultados do Google
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and "url?q=" in href:
                        clean_url = href.split("url?q=")[1].split("&sa=")[0]
                        if "google.com" not in clean_url:
                            results.append(clean_url)
            time.sleep(2) # Evitar block
        except Exception as e:
            print(f"Erro no scan: {e}")
            
    return list(set(results))

def run_scanner():
    print("Iniciando varredura Sentinel...")
    profiles = database.get_profiles()
    
    for p in profiles:
        p_id, name, cpf, phone, rg, _ = p
        
        # 1. Busca pelo Nome
        print(f"Buscando por: {name}")
        findings = google_dork_scan(name)
        for link in findings:
            if database.add_finding(p_id, "Google Dork (Nome)", f"Menção encontrada ao nome {name}", link):
                # Se for um achado novo, notifica
                msg = f"⚠️ **ALERTA DE EXPOSIÇÃO** ⚠️\n\n👤 Perfil: {name}\n🔗 Fonte: Google Dork\n📄 Link: {link}"
                bot.send_message(CHAT_ID, msg)
        
        # 2. Busca pelo CPF
        if cpf:
            print(f"Buscando por: {cpf}")
            findings_cpf = google_dork_scan(cpf)
            for link in findings_cpf:
                if database.add_finding(p_id, "Google Dork (CPF)", f"CPF {cpf} encontrado em texto plano", link):
                    msg = f"‼️ **ALERTA DE RISCO ALTO (CPF)** ‼️\n\n👤 Perfil: {name}\n💳 CPF detectado: {cpf}\n🔗 Link: {link}"
                    bot.send_message(CHAT_ID, msg)

        # 3. Busca pelo RG
        if rg:
            print(f"Buscando por: {rg}")
            findings_rg = google_dork_scan(rg)
            for link in findings_rg:
                if database.add_finding(p_id, "Google Dork (RG)", f"RG {rg} detectado", link):
                    msg = f"⚠️ **ALERTA (RG)** ⚠️\n\n👤 Perfil: {name}\n🆔 RG detectado: {rg}\n🔗 Link: {link}"
                    bot.send_message(CHAT_ID, msg)

    print("Varredura concluída.")

if __name__ == "__main__":
    run_scanner()
