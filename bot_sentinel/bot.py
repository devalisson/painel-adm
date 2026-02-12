import telebot
from telebot import types
import database
import os

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
/newprofile - Adicionar novo perfil para vigiar
/list - Ver perfis sendo monitorados
/remove - Deletar um perfil
/scan - Rodar varredura agora
    """
    bot.reply_to(message, msg, parse_mode='Markdown')

@bot.message_handler(commands=['newprofile'])
def cmd_new_profile(message):
    chat_id = message.chat_id
    user_data[chat_id] = Profile()
    msg = bot.send_message(chat_id, "👤 Digite o **Nome Completo** para monitorar:")
    bot.register_next_step_handler(msg, process_name_step)

def process_name_step(message):
    chat_id = message.chat_id
    user_data[chat_id].name = message.text
    msg = bot.send_message(chat_id, "💳 Digite o **CPF** (apenas números ou com pontos):")
    bot.register_next_step_handler(msg, process_cpf_step)

def process_cpf_step(message):
    chat_id = message.chat_id
    user_data[chat_id].cpf = message.text
    msg = bot.send_message(chat_id, "📱 Digite o **Telefone** (ex: 11999999999):")
    bot.register_next_step_handler(msg, process_phone_step)

def process_phone_step(message):
    chat_id = message.chat_id
    user_data[chat_id].phone = message.text
    msg = bot.send_message(chat_id, "🆔 Digite o **RG** (opcional - digite 'pular' se não quiser):")
    bot.register_next_step_handler(msg, process_rg_step)

def process_rg_step(message):
    chat_id = message.chat_id
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
    except IndexError:
        bot.reply_to(message, "⚠️ Informe o ID. Ex: /delete 1")

# O loop do bot
if __name__ == "__main__":
    print("Bot Sentinel em execução...")
    bot.infinity_polling()
