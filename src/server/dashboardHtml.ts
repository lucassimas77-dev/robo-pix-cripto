export function renderDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Robô Pix ➔ Carteira Cripto</title>
  <style>
    :root {
      --bg: #0b141a;
      --card: #111b21;
      --card-2: #202c33;
      --green: #00a884;
      --green-hover: #06cf9c;
      --text: #e9edef;
      --muted: #8696a0;
      --border: #2a3942;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; padding: 24px 16px; }
    .container { max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }
    header { text-align: center; margin-bottom: 6px; position: relative; }
    header h1 { font-size: 22px; margin-bottom: 6px; }
    header p { color: var(--muted); font-size: 14px; }
    .step-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .auth-box { max-width: 440px; margin: 40px auto; }
    .step-title { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .step-title h2 { font-size: 17px; display: flex; align-items: center; gap: 8px; }
    .pill {
      padding: 4px 11px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      background: rgba(0,168,132,0.18);
      color: #34d399;
    }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 680px) { .grid-2 { grid-template-columns: 1fr; } }
    label { display: flex; flex-direction: column; gap: 5px; font-size: 13px; color: var(--muted); }
    input, select {
      background: var(--card-2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
    }
    input:focus, select:focus { border-color: var(--green); }
    .btn {
      background: var(--green);
      color: #05221b;
      font-weight: 700;
      border: none;
      padding: 11px 18px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
    }
    .btn:hover { background: var(--green-hover); }
    .btn-red { background: var(--danger); color: #fff; }
    .btn-ghost {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--muted);
      padding: 6px 12px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 12px;
    }
    .wa-flex { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
    .qr-box {
      width: 180px;
      height: 180px;
      background: var(--card-2);
      border: 1px dashed var(--border);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 8px;
      font-size: 12.5px;
      color: var(--muted);
    }
    .qr-box img { width: 100%; height: 100%; border-radius: 8px; background: #fff; }
    .order-row {
      background: var(--card-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }
    .info-banner {
      background: rgba(0, 168, 132, 0.1);
      border: 1px solid rgba(0, 168, 132, 0.3);
      color: #a7f3d0;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      line-height: 1.45;
    }
    .toast { color: #34d399; font-size: 13px; font-weight: 600; }
    .err-msg { color: #f87171; font-size: 13px; font-weight: 600; }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>⚡ Automação Pix ➔ Carteira Cripto pelo WhatsApp</h1>
      <p>Modo Privado Automático: o cliente envia o valor no WhatsApp e recebe o pagamento na hora sem perguntas.</p>
    </header>

    <!-- TELA DE PROTEÇÃO POR SENHA (PRIMEIRO ACESSO OU LOGIN) -->
    <section id="authCard" class="step-card auth-box hidden">
      <h2 id="authTitle">🔒 Proteção do Painel</h2>
      <p id="authDesc" style="font-size:13.5px;color:var(--muted);line-height:1.45;"></p>
      <label>
        Senha do Painel
        <input id="authPassword" type="password" placeholder="Digite sua senha (mín. 4 caracteres)..." />
      </label>
      <button id="authBtn" class="btn" type="button">Entrar</button>
      <span id="authErr" class="err-msg"></span>
    </section>

    <!-- PAINEL PRINCIPAL AUTENTICADO -->
    <div id="mainApp" class="hidden" style="display:flex;flex-direction:column;gap:20px;">
      <div style="display:flex;justify-content:flex-end;">
        <button id="logoutBtn" class="btn-ghost" type="button">🔒 Sair do Painel</button>
      </div>

      <!-- PASSO 1: CONTA E CARTEIRA -->
      <section class="step-card">
        <div class="step-title">
          <h2>1️⃣ Conectar Sua Conta & Carteira Cripto</h2>
          <span id="accBadge" class="pill">Carregando...</span>
        </div>

        <div class="grid-2">
          <label>
            Plataforma Conversora (Pix ➔ Cripto)
            <select id="provider">
              <option value="depixapp">DePix App (Liquid Network - DePix Autocustódia)</option>
              <option value="hodle">Hodle (USDT / USDC - Base / Polygon)</option>
              <option value="noxpay">NoxPay CrossRamp (USDT / BTC)</option>
              <option value="mock">Modo Teste Interno (Simular sem dinheiro real)</option>
            </select>
          </label>
          <label id="apiKeyLabel">
            Chave de API da Plataforma (sk_live_... ou sk_test_...)
            <input id="apiKey" type="password" placeholder="Cole aqui a chave da sua conta..." />
          </label>
        </div>

        <div id="depixWalletNotice" class="info-banner hidden">
          ℹ️ <strong>Carteira Automática na DePix App:</strong> Os pagamentos via Pix caem sempre em <strong>DEPIX (Rede Liquid)</strong> diretamente no endereço Liquid configurado dentro da sua conta em <strong>depixapp.com/#merchant</strong> (por segurança da API deles, ninguém consegue desviar sua carteira por fora).
        </div>

        <div id="customWalletFields" class="grid-2 hidden">
          <label>
            Endereço da Sua Carteira Cripto
            <input id="walletAddress" placeholder="Ex: 0x..." />
          </label>
          <label>
            Moeda / Rede da Carteira
            <div style="display:flex;gap:8px;">
              <input id="walletAsset" placeholder="USDT" style="width:50%;" />
              <input id="walletNetwork" placeholder="POLYGON" style="width:50%;" />
            </div>
          </label>
        </div>

        <div id="webhookFieldWrap" class="grid-2">
          <label>
            Segredo de Webhook (Opcional — já consultamos pagamentos automaticamente!)
            <input id="webhookSecret" type="password" placeholder="Opcional (whsec_...)" />
          </label>
          <label>
            WhatsApp p/ Receber Avisos de Venda (Opcional)
            <input id="adminPhone" placeholder="Ex: 5511999998888" />
          </label>
        </div>

        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
          <button id="saveAccBtn" class="btn" type="button">💾 Salvar Conta & Carteira</button>
          <span id="saveMsg" class="toast"></span>
        </div>
      </section>

      <!-- PASSO 2: WHATSAPP -->
      <section class="step-card">
        <div class="step-title">
          <h2>2️⃣ Conectar o WhatsApp que Vai Atender</h2>
          <span id="waBadge" class="pill">DESCONECTADO</span>
        </div>
        <div class="wa-flex">
          <div style="flex:1;min-width:260px;display:flex;flex-direction:column;gap:12px;">
            <label>
              Quem o robô deve responder nesse WhatsApp?
              <select id="filterMode">
                <option value="keyword_only">🔒 Só responder quando falarem "Pix" ou "Pagar" (Não atrapalha conversas pessoais)</option>
                <option value="all">📢 Responder qualquer mensagem (Para chip exclusivo de vendas)</option>
              </select>
            </label>
            <label>
              Opcional: Restringir teste apenas a 1 telefone (ex: 5511999998888)
              <input id="allowedPhone" placeholder="Deixe vazio para atender qualquer cliente que pedir Pix" />
            </label>
            <span id="waFilterErr" class="err-msg"></span>
            <div style="display:flex;gap:10px;flex-wrap:wrap;">
              <button id="connectWaBtn" class="btn" type="button">📲 Gerar QR Code do WhatsApp</button>
              <button id="disconnectWaBtn" class="btn btn-red" type="button">Desconectar WhatsApp</button>
            </div>
            <p id="waHint" style="font-size:13px;color:var(--muted);"></p>
          </div>
          <div id="qrBox" class="qr-box">Clique em "Gerar QR Code" ao lado</div>
        </div>
      </section>

      <!-- PASSO 3: PAGAMENTOS EM TEMPO REAL -->
      <section class="step-card">
        <div class="step-title">
          <h2>3️⃣ Cobranças Pix Geradas & Pagamentos Confirmados</h2>
          <span style="font-size:12px;color:var(--muted);">Atualiza sozinho</span>
        </div>
        <div id="ordersList" style="display:flex;flex-direction:column;gap:10px;"></div>
      </section>
    </div>
  </div>

  <script>
    const authCard = document.getElementById('authCard');
    const authTitle = document.getElementById('authTitle');
    const authDesc = document.getElementById('authDesc');
    const authPassword = document.getElementById('authPassword');
    const authBtn = document.getElementById('authBtn');
    const authErr = document.getElementById('authErr');
    const mainApp = document.getElementById('mainApp');
    const logoutBtn = document.getElementById('logoutBtn');

    const providerEl = document.getElementById('provider');
    const apiKeyLabel = document.getElementById('apiKeyLabel');
    const apiKeyEl = document.getElementById('apiKey');
    const depixWalletNotice = document.getElementById('depixWalletNotice');
    const customWalletFields = document.getElementById('customWalletFields');
    const webhookFieldWrap = document.getElementById('webhookFieldWrap');
    const webhookSecretEl = document.getElementById('webhookSecret');
    const adminPhoneEl = document.getElementById('adminPhone');
    const walletAddressEl = document.getElementById('walletAddress');
    const walletAssetEl = document.getElementById('walletAsset');
    const walletNetworkEl = document.getElementById('walletNetwork');
    const accBadge = document.getElementById('accBadge');
    const saveAccBtn = document.getElementById('saveAccBtn');
    const saveMsg = document.getElementById('saveMsg');

    const waBadge = document.getElementById('waBadge');
    const qrBox = document.getElementById('qrBox');
    const waHint = document.getElementById('waHint');
    const waFilterErr = document.getElementById('waFilterErr');
    const filterModeEl = document.getElementById('filterMode');
    const allowedPhoneEl = document.getElementById('allowedPhone');
    const connectWaBtn = document.getElementById('connectWaBtn');
    const disconnectWaBtn = document.getElementById('disconnectWaBtn');
    const ordersList = document.getElementById('ordersList');

    let needsSetupMode = false;
    let pollTimer = null;
    let waSettingsLoadedOnce = false;

    function updateProviderVisibility() {
      const prov = providerEl.value;
      if (prov === 'depixapp') {
        depixWalletNotice.classList.remove('hidden');
        customWalletFields.classList.add('hidden');
        apiKeyLabel.classList.remove('hidden');
        webhookFieldWrap.classList.remove('hidden');
      } else if (prov === 'mock') {
        depixWalletNotice.classList.add('hidden');
        customWalletFields.classList.add('hidden');
        apiKeyLabel.classList.add('hidden');
        webhookFieldWrap.classList.add('hidden');
      } else {
        depixWalletNotice.classList.add('hidden');
        customWalletFields.classList.remove('hidden');
        apiKeyLabel.classList.remove('hidden');
        webhookFieldWrap.classList.remove('hidden');
        if (!walletAssetEl.value || walletAssetEl.value.toUpperCase() === 'DEPIX') {
          walletAssetEl.value = 'USDT';
        }
        if (!walletNetworkEl.value || walletNetworkEl.value.toUpperCase() === 'LIQUID') {
          walletNetworkEl.value = 'POLYGON';
        }
      }
    }

    providerEl.addEventListener('change', updateProviderVisibility);

    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (data.authenticated) {
          authCard.classList.add('hidden');
          mainApp.classList.remove('hidden');
          await loadAccount();
          await pollStatus();
          if (!pollTimer) {
            pollTimer = setInterval(pollStatus, 4000);
          }
          return;
        }

        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
        mainApp.classList.add('hidden');
        authCard.classList.remove('hidden');
        needsSetupMode = Boolean(data.needsSetup);

        if (needsSetupMode) {
          authTitle.textContent = '🔐 Crie uma Senha Rápida para o Painel';
          authDesc.textContent = 'Como este link é público na nuvem, defina uma senha curta agora para que somente você (ou seu amigo) possa mexer na carteira e no WhatsApp.';
          authBtn.textContent = 'Salvar Senha e Abrir Painel';
        } else {
          authTitle.textContent = '🔒 Painel Protegido';
          authDesc.textContent = 'Digite a senha definida no primeiro acesso para abrir o painel.';
          authBtn.textContent = 'Entrar no Painel';
        }
      } catch {
        authErr.textContent = 'Conexão temporariamente indisponível. Tentando novamente...';
      }
    }

    async function submitAuth() {
      authErr.textContent = '';
      const pwd = authPassword.value.trim();
      if (!pwd) {
        authErr.textContent = 'Digite uma senha.';
        return;
      }
      authBtn.disabled = true;
      try {
        const endpoint = needsSetupMode ? '/api/auth/setup' : '/api/auth/login';
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pwd })
        });
        const out = await res.json();
        if (!res.ok) {
          authErr.textContent = out.error || 'Falha ao autenticar.';
          return;
        }
        authPassword.value = '';
        await checkAuth();
      } catch {
        authErr.textContent = 'Falha de rede ao autenticar. Tente novamente.';
      } finally {
        authBtn.disabled = false;
      }
    }

    authBtn.addEventListener('click', submitAuth);
    authPassword.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submitAuth();
    });

    logoutBtn.addEventListener('click', async () => {
      try {
        await fetch('/api/auth/logout', { method: 'POST' });
      } catch {
        // Ignora
      }
      await checkAuth();
    });

    async function loadAccount() {
      try {
        const res = await fetch('/api/account');
        if (res.status === 401) {
          await checkAuth();
          return;
        }
        const acc = await res.json();
        providerEl.value = acc.provider;
        walletAddressEl.value = acc.walletAddress || '';
        walletAssetEl.value = acc.walletAsset || 'USDT';
        walletNetworkEl.value = acc.walletNetwork || 'POLYGON';
        adminPhoneEl.value = acc.adminWhatsappPhone || '';

        apiKeyEl.placeholder = acc.apiKeyPreview
          ? 'Salva (' + acc.apiKeyPreview + ') - digite p/ trocar'
          : 'Cole aqui a chave da sua conta...';

        webhookSecretEl.placeholder = acc.hasWebhookSecret
          ? 'Segredo salvo - digite p/ trocar'
          : 'Opcional (whsec_...)';

        if (acc.provider === 'mock') {
          accBadge.textContent = 'MODO TESTE INTERNO (SEM DINHEIRO REAL)';
        } else if (!acc.hasApiKey) {
          accBadge.textContent = 'AGUARDANDO COLAR CHAVE DE API';
        } else if (acc.isTestKey) {
          accBadge.textContent = '🧪 CHAVE DE TESTE ATIVA (' + acc.provider.toUpperCase() + ')';
        } else {
          accBadge.textContent = '✅ CONTA REAL ATIVA (' + acc.provider.toUpperCase() + ')';
        }

        updateProviderVisibility();
      } catch {
        // Ignora oscilação momentânea
      }
    }

    saveAccBtn.addEventListener('click', async () => {
      saveMsg.textContent = 'Salvando...';
      saveAccBtn.disabled = true;
      try {
        const res = await fetch('/api/account', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: providerEl.value,
            apiKey: apiKeyEl.value,
            webhookSecret: webhookSecretEl.value,
            walletAddress: walletAddressEl.value,
            walletAsset: walletAssetEl.value,
            walletNetwork: walletNetworkEl.value,
            adminWhatsappPhone: adminPhoneEl.value
          })
        });
        if (res.status === 401) {
          await checkAuth();
          return;
        }
        apiKeyEl.value = '';
        webhookSecretEl.value = '';
        saveMsg.textContent = res.ok ? '✅ Configuração salva e ativa!' : '⚠️ Erro ao salvar.';
        setTimeout(() => { saveMsg.textContent = ''; }, 3500);
        await loadAccount();
      } catch {
        saveMsg.textContent = '⚠️ Falha de conexão ao salvar.';
      } finally {
        saveAccBtn.disabled = false;
      }
    });

    async function saveWaFilter() {
      waFilterErr.textContent = '';
      try {
        const res = await fetch('/api/whatsapp/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filterMode: filterModeEl.value,
            allowedTestPhone: allowedPhoneEl.value
          })
        });
        if (!res.ok) {
          const out = await res.json();
          waFilterErr.textContent = out.error || 'Telefone inválido.';
        }
      } catch {
        // Ignora
      }
    }

    filterModeEl.addEventListener('change', saveWaFilter);
    allowedPhoneEl.addEventListener('change', saveWaFilter);

    connectWaBtn.addEventListener('click', async () => {
      waFilterErr.textContent = '';
      qrBox.textContent = 'Gerando QR Code...';
      try {
        const res = await fetch('/api/whatsapp/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filterMode: filterModeEl.value,
            allowedTestPhone: allowedPhoneEl.value
          })
        });
        if (!res.ok) {
          const out = await res.json();
          waFilterErr.textContent = out.error || 'Configuração inválida.';
          qrBox.textContent = 'Corrija o telefone ao lado.';
          return;
        }
        await pollStatus();
      } catch {
        qrBox.textContent = 'Erro de conexão. Tente novamente.';
      }
    });

    disconnectWaBtn.addEventListener('click', async () => {
      try {
        await fetch('/api/whatsapp/disconnect', { method: 'POST' });
        await pollStatus();
      } catch {
        // Ignora
      }
    });

    async function simulatePay(orderId) {
      try {
        await fetch('/api/simulator/pay/' + encodeURIComponent(orderId), { method: 'POST' });
        await pollStatus();
      } catch {
        // Ignora
      }
    }

    function renderQrBoxSafe(wa) {
      qrBox.replaceChildren();
      if (wa.state === 'CONNECTED') {
        const badgeDiv = document.createElement('div');
        badgeDiv.style.color = '#34d399';
        badgeDiv.style.fontWeight = '700';
        badgeDiv.textContent = '🟢 Conectado! +' + String(wa.connectedPhone || '');
        qrBox.appendChild(badgeDiv);
        waHint.textContent = 'Tudo pronto! Basta alguém mandar "Me manda um Pix de 50" para esse WhatsApp.';
      } else if (
        wa.state === 'QR_READY' &&
        typeof wa.qrCodeDataUrl === 'string' &&
        /^data:image\\/png;base64,[A-Za-z0-9+/=]+$/.test(wa.qrCodeDataUrl)
      ) {
        const img = document.createElement('img');
        img.src = wa.qrCodeDataUrl;
        img.alt = 'QR Code WhatsApp';
        qrBox.appendChild(img);
        waHint.textContent = 'No celular: Abra o WhatsApp > Aparelhos Conectados > Conectar Aparelho e aponte para o QR ao lado.';
      } else if (wa.state === 'CONNECTING') {
        qrBox.textContent = 'Aguarde...';
      } else {
        qrBox.textContent = 'Clique em "Gerar QR Code"';
        waHint.textContent = wa.lastError ? String(wa.lastError) : '';
      }
    }

    function renderOrdersSafe(orders) {
      ordersList.replaceChildren();
      if (!Array.isArray(orders) || orders.length === 0) {
        const p = document.createElement('p');
        p.style.color = 'var(--muted)';
        p.style.fontSize = '13.5px';
        p.textContent = 'Nenhum Pix solicitado ainda. Assim que alguém pedir no WhatsApp, aparecerá aqui!';
        ordersList.appendChild(p);
        return;
      }

      for (const o of orders) {
        const row = document.createElement('div');
        row.className = 'order-row';

        const left = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = Number(o.amountBrl || 0).toLocaleString('pt-BR', {
          style: 'currency',
          currency: 'BRL'
        });
        const phoneSpan = document.createElement('span');
        phoneSpan.style.color = 'var(--muted)';
        phoneSpan.style.fontSize = '13px';
        phoneSpan.textContent = ' (Cliente: +' + String(o.customerPhoneMasked || '') + ')';
        left.appendChild(strong);
        left.appendChild(phoneSpan);

        const right = document.createElement('div');
        right.style.display = 'flex';
        right.style.alignItems = 'center';
        right.style.gap = '10px';

        if (o.status === 'PENDING' && o.provider === 'mock') {
          const simBtn = document.createElement('button');
          simBtn.type = 'button';
          simBtn.className = 'btn';
          simBtn.style.padding = '6px 12px';
          simBtn.style.fontSize = '12px';
          simBtn.textContent = 'Simular Pagamento (Teste)';
          simBtn.addEventListener('click', () => simulatePay(String(o.id)));
          right.appendChild(simBtn);
        }

        const pill = document.createElement('span');
        pill.className = 'pill';
        pill.textContent = String(o.status || '');
        right.appendChild(pill);

        row.appendChild(left);
        row.appendChild(right);
        ordersList.appendChild(row);
      }
    }

    async function pollStatus() {
      try {
        const [waRes, ordRes] = await Promise.all([
          fetch('/api/whatsapp/status'),
          fetch('/api/orders')
        ]);
        if (waRes.status === 401 || ordRes.status === 401) {
          await checkAuth();
          return;
        }
        const wa = await waRes.json();
        const orders = await ordRes.json();

        if (!waSettingsLoadedOnce) {
          if (wa.filterMode === 'all' || wa.filterMode === 'keyword_only') {
            filterModeEl.value = wa.filterMode;
          }
          if (typeof wa.allowedTestPhone === 'string' && document.activeElement !== allowedPhoneEl) {
            allowedPhoneEl.value = wa.allowedTestPhone;
          }
          waSettingsLoadedOnce = true;
        }

        waBadge.textContent = wa.state === 'CONNECTED' ? '🟢 WHATSAPP CONECTADO' : String(wa.state || 'DESCONECTADO');
        renderQrBoxSafe(wa);
        renderOrdersSafe(orders);
      } catch {
        // Ignora oscilação momentânea de rede sem estourar Promise rejeitada
      }
    }

    checkAuth();
  </script>
</body>
</html>`;
}
