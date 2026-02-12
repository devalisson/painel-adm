#!/bin/bash

echo "🚀 Iniciando Setup do Sentinel Bot na VPS..."

# 1. Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# 2. Instalar Python e Pip se não existirem
sudo apt install python3 python3-pip -y

# 3. Entrar na pasta (assumindo que o usuário colou a pasta do bot)
cd "$(dirname "$0")"

# 4. Instalar dependências
pip3 install -r requirements.txt

# 5. Inicializar banco de dados
python3 database.py

echo "✅ Ambiente pronto!"
echo "------------------------------------------------"
echo "Para rodar o bot: python3 bot.py"
echo "Para rodar o scanner manual: python3 scanner.py"
echo "------------------------------------------------"
echo "Dica: Use 'screen' ou 'nohup' para manter o bot rodando 24/7."
