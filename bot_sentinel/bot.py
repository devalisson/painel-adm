import telebot
from telebot import types
import database
import os
import report_generator
from datetime import datetime

# Configuração
API_TOKEN = 'SEU_TOKEN_AQUI' # O usuário deve substituir pelo seu token
bot = telebot.TeleBot(API_TOKEN)

# Inicializa banco de dados
database.init_db()

user_data = {}

class Profile:
    def __init__(self):
        self.name = None
        self.cpf = None
        self.phone = None
        self.rg = None

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    msg = """🛡️ **Sentinel Bot v1.0**
Sistema de monitoramento OSINT para proteção pessoal.

**Comandos:**
/newprofile - Adicionar novo perfil para vigiar (Nome, CPF, Tel, RG)
/list - Ver perfis sendo monitorados
/remove - Deletar um perfil
/report - Gerar relatorio PDF agora (últimas 24h)
/scan - Rodar varredura agora
    """
    bot.reply_to(message, msg, parse_mode='Markdown')

@bot.message_handler(commands=['newprofile'])
def cmd_new_profile(message):
    chat_id = message.chat.id
    user_data[chat_id] = Profile()
    msg = bot.send_message(chat_id, "👤 Digite o **Nome Completo** para monitorar:")
    bot.register_next_step_handler(msg, process_name_step)

def process_name_step(message):
    chat_id = message.chat.id
    user_data[chat_id].name = message.text
    msg = bot.send_message(chat_id, "💳 Digite o **CPF** (apenas números ou com pontos):")
    bot.register_next_step_handler(msg, process_cpf_step)

def process_cpf_step(message):
    chat_id = message.chat.id
    user_data[chat_id].cpf = message.text
    msg = bot.send_message(chat_id, "📱 Digite o **Telefone** (ex: 11999999999):")
    bot.register_next_step_handler(msg, process_phone_step)

def process_phone_step(message):
    chat_id = message.chat.id
    user_data[chat_id].phone = message.text
    msg = bot.send_message(chat_id, "🆔 Digite o **RG** (opcional - digite 'pular' se não quiser):")
    bot.register_next_step_handler(msg, process_rg_step)

def process_rg_step(message):
    chat_id = message.chat.id
    rg = message.text
    if rg.lower() == 'pular':
        rg = ""
    user_data[chat_id].rg = rg
    
    p = user_data[chat_id]
    database.add_profile(p.name, p.cpf, p.phone, p.rg)
    
    bot.send_message(chat_id, f"✅ **Perfil Salvo com Sucesso!**\n\nNome: {p.name}\nCPF: {p.cpf}\nTel: {p.phone}\nRG: {rg}\n\nIniciando monitoramento 24/7...", parse_mode='Markdown')
    del user_data[chat_id]

@bot.message_handler(commands=['list'])
def cmd_list(message):
    profiles = database.get_profiles()
    if not profiles:
        bot.reply_to(message, "Nenhum perfil cadastrado no momento.")
        return
    
    resp = "📋 **Perfis Monitorados:**\n\n"
    for p in profiles:
        resp += f"🆔 ID: {p[0]}\n👤 Nome: {p[1]}\n💳 CPF: {p[2]}\n📱 Tel: {p[3]}\n\n"
    
    bot.send_message(message.chat.id, resp, parse_mode='Markdown')

@bot.message_handler(commands=['remove'])
def cmd_remove(message):
    bot.reply_to(message, "Digite `/delete [ID]` para remover um perfil (ex: `/delete 1`)", parse_mode='Markdown')

@bot.message_handler(commands=['delete'])
def cmd_delete_id(message):
    try:
        profile_id = message.text.split()[1]
        database.remove_profile(profile_id)
        bot.reply_to(message, f"🗑️ Perfil {profile_id} removido.")
    except Exception as e:
        bot.reply_to(message, "⚠️ Informe o ID corretamente. Ex: /delete 1")

@bot.message_handler(commands=['report'])
def cmd_report(message):
    chat_id = message.chat.id
    profiles = database.get_profiles()
    
    if not profiles:
        bot.send_message(chat_id, "Nenhum perfil cadastrado para gerar relatorio.")
        return
    
    bot.send_message(chat_id, "⏳ Analisando dados e gerando relatorio PDF. Por favor, aguarde...")
    
    for p in profiles:
        p_id = p[0]
        name = p[1]
        findings = database.get_recent_findings(p_id)
        
        filename = f"relatorio_{name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        pdf_path = report_generator.generate_pdf_report(p, findings, filename)
        
        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as pdf_file:
                bot.send_document(chat_id, pdf_file, caption=f"📄 Relatório Sentinel 24h: {name}")
            os.remove(pdf_path)
        else:
            bot.send_message(chat_id, f"❌ Erro ao gerar o PDF para o perfil: {name}")

@bot.message_handler(commands=['scan'])
def cmd_scan(message):
    bot.reply_to(message, "🔎 Iniciando varredura manual em todas as fontes. Voce recebera alertas se algo for encontrado.")
    # Aqui poderíamos chamar o scanner diretamente ou via subprocess
    import scanner
    scanner.run_scanner()
    bot.send_message(message.chat.id, "✅ Varredura manual concluída.")

if __name__ == "__main__":
    print("Bot Sentinel em execução...")
    bot.infinity_polling()
