# 🛡️ Systems Sentinel — Cyber Intelligence Dashboard

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Tools](https://img.shields.io/badge/tools-317+-purple)

**Painel de monitoramento de ecossistema digital com console de inteligência cibernética e guia de proteção pessoal.**

[Dashboard](#-dashboard) • [Console OSINT](#-console-osint) • [Guia de Proteção](#-guia-de-proteção) • [Deploy](#-deploy)

</div>

---

## 📋 Sobre

O **Systems Sentinel** é um painel completo para monitoramento e inteligência digital, composto por três módulos:

| Módulo | Arquivo | Descrição |
|--------|---------|-----------|
| 🖥️ **Dashboard** | `index.html` | Monitoramento de status de sistemas em tempo real |
| 🔐 **Console OSINT** | `admin.html` | 317+ ferramentas de inteligência em 75 categorias |
| 🛡️ **Proteção Digital** | `protecao.html` | Guia com 200+ ferramentas de privacidade em 8 camadas |

## ✨ Funcionalidades

### Dashboard de Status
- Monitoramento de serviços em tempo real
- Cards com status (Online/Offline/Pendente)
- Animações e efeitos visuais premium
- Acesso protegido por senha ao console OSINT

### Console de Inteligência (OSINT)
- **317+ ferramentas** organizadas em **75 categorias**
- Busca instantânea com filtro por categoria
- README do GitHub integrado para cada ferramenta
- Guias de instalação multi-OS (Linux, Windows, Termux, Web)
- Terminal simulado com logs em tempo real
- Badges de OS e tags WEB para ferramentas via navegador

### Guia de Proteção Digital
- **8 camadas de segurança** — do básico ao profissional
- 200+ ferramentas com links diretos para os sites oficiais
- Plano de implementação em 4 níveis (Grátis → $1000+/ano)
- Checklists interativas (mensal, trimestral, anual)
- Workflows práticos e configurações recomendadas
- Tabela de erros comuns a evitar

## 🚀 Deploy

### GitHub Pages (Recomendado)

1. Faça um **fork** ou clone este repositório
2. Vá em **Settings → Pages**
3. Em **Source**, selecione a branch `main` e pasta `/`
4. Clique em **Save**
5. Acesse via `https://seu-usuario.github.io/nome-do-repo/`

### Netlify

1. Conecte o repositório no [Netlify](https://netlify.com)
2. Build command: _(deixe vazio)_
3. Publish directory: `.`
4. Deploy automático a cada push

### Vercel

1. Importe o repositório no [Vercel](https://vercel.com)
2. Framework preset: **Other**
3. Deploy com um clique

### Local

Basta abrir `index.html` no navegador — não precisa de servidor.

## 📁 Estrutura

```
├── index.html        # Dashboard de status
├── style.css         # Estilos do dashboard
├── script.js         # Lógica do dashboard
├── admin.html        # Console OSINT
├── admin.css         # Estilos do console
├── admin.js          # Dados e lógica (317+ ferramentas)
├── protecao.html     # Guia de proteção digital
├── protecao.css      # Estilos do guia
├── README.md         # Este arquivo
├── LICENSE           # MIT License
└── .gitignore        # Arquivos ignorados
```

## 🔑 Acesso

- **Dashboard**: Aberto — `index.html`
- **Console OSINT**: Protegido por senha — botão `ACCESS_SHADOW_NET`
- **Guia de Proteção**: Aberto — botão `🛡️ SE PROTEJA`

## 🛠️ Tecnologias

- HTML5 semântico
- CSS3 (glassmorphism, gradientes, animações)
- JavaScript vanilla (sem frameworks)
- Google Fonts (Outfit, Inter)
- 100% client-side — sem backend necessário

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

---

<div align="center">
  <strong>⚡ Feito com propósito educacional ⚡</strong>
</div>
