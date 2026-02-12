const systems = [
    {
        name: "EcomFlow",
        url: "https://ecomflow-dusky.vercel.app/",
        id: "ecomflow"
    },
    {
        name: "Scalebot Dashboard",
        url: "https://scalebot.sbs/dashboard",
        id: "scalebot"
    },
    {
        name: "Gerador de Nomes",
        url: "https://brunalopeesss852-maker.github.io/site-gerador-de-nome/",
        id: "namegen"
    },
    {
        name: "Projeto Maker",
        url: "https://deft-monstera-221d39.netlify.app/",
        id: "maker"
    },
    {
        name: "Planos One",
        url: "https://planos-one.vercel.app/",
        id: "planos"
    },
    {
        name: "Chat Hub",
        url: "https://chat-hub-vert.vercel.app/",
        id: "chathub"
    },
    {
        name: "Escola de Prompt",
        url: "https://escola-de-prompt.vercel.app/",
        id: "escola"
    }
];

function createCard(system) {
    return `
        <a href="${system.url}" target="_blank" class="card" id="card-${system.id}">
            <div class="card-header">
                <div class="logo-icon small"></div>
                <div class="status-badge status-pending-badge" id="badge-${system.id}">Analisando</div>
            </div>
            <h2>${system.name}</h2>
            <div class="url-text">${system.url}</div>
            <div class="performance-info">
                <div class="ping-bar">
                    <div class="ping-fill" id="ping-${system.id}"></div>
                </div>
                <span class="url-text" id="time-${system.id}">-- ms</span>
            </div>
        </a>
    `;
}

async function checkStatus(system) {
    const startTime = performance.now();
    const badge = document.getElementById(`badge-${system.id}`);
    const timeText = document.getElementById(`time-${system.id}`);
    const pingFill = document.getElementById(`ping-${system.id}`);

    try {
        // Usamos modo 'no-cors' para evitar problemas de CORS, 
        // mas isso limita o que podemos ler. 
        // Para um monitoramento real e preciso de status HTTP (200, 404, etc), 
        // seria necessário um proxy backend.
        // Aqui simulamos a latência e conectividade básica.
        const response = await fetch(system.url, { mode: 'no-cors', cache: 'no-cache' });
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);

        badge.textContent = "Online";
        badge.className = "status-badge status-online-badge";
        timeText.textContent = `${duration} ms`;

        // Simulação visual de performance (verde se < 500ms, amarelo < 1s, vermelho > 1s)
        const percent = Math.min(100, Math.max(10, 100 - (duration / 20)));
        pingFill.style.width = `${percent}%`;

        return true;
    } catch (error) {
        badge.textContent = "Offline";
        badge.className = "status-badge status-offline-badge";
        timeText.textContent = "Erro";
        pingFill.style.width = "0%";
        return false;
    }
}

async function updateAllStatuses() {
    const grid = document.getElementById('systems-grid');
    const overallStatus = document.getElementById('overall-status');
    const pulseIcon = document.querySelector('.pulse-icon');

    let onlineCount = 0;

    const results = await Promise.all(systems.map(s => checkStatus(s)));
    onlineCount = results.filter(r => r).length;

    document.getElementById('last-update').textContent = `Última atualização: ${new Date().toLocaleTimeString()}`;

    if (onlineCount === systems.length) {
        overallStatus.textContent = "Todos os sistemas operacionais";
        pulseIcon.style.backgroundColor = "#00ff88";
        pulseIcon.style.boxShadow = "0 0 10px #00ff88";
    } else if (onlineCount > 0) {
        overallStatus.textContent = `${onlineCount}/${systems.length} Sistemas Online`;
        pulseIcon.style.backgroundColor = "#ffd900";
        pulseIcon.style.boxShadow = "0 0 10px #ffd900";
    } else {
        overallStatus.textContent = "Todos os sistemas offline";
        pulseIcon.style.backgroundColor = "#ff3e3e";
        pulseIcon.style.boxShadow = "0 0 10px #ff3e3e";
    }
}

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
    const grid = document.getElementById('systems-grid');
    grid.innerHTML = systems.map(s => createCard(s)).join('');

    updateAllStatuses();

    // Atualiza a cada 30 segundos
    setInterval(updateAllStatuses, 30000);

    // Lógica do Modal de Senha
    const modal = document.getElementById('password-modal');
    const btnHacker = document.getElementById('btn-hacker-adm');
    const btnCancel = document.getElementById('btn-cancel');
    const btnConfirm = document.getElementById('btn-confirm');
    const passInput = document.getElementById('admin-password');
    const errorMsg = document.getElementById('password-error');

    btnHacker.addEventListener('click', () => {
        modal.style.display = 'flex';
        passInput.focus();
    });

    btnCancel.addEventListener('click', () => {
        modal.style.display = 'none';
        passInput.value = '';
        errorMsg.textContent = '';
    });

    function verifyPass() {
        if (passInput.value === 'admin123') {
            window.location.href = 'admin';
        } else {
            errorMsg.textContent = 'ACCESS_DENIED: INVALID_KEY';
            passInput.value = '';
            passInput.classList.add('shake');
            setTimeout(() => passInput.classList.remove('shake'), 400);
        }
    }

    btnConfirm.addEventListener('click', verifyPass);
    passInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') verifyPass();
    });
});
