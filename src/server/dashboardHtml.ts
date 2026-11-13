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
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; padding: 24px 16px; }
    .container { max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }
    header { text-align: center; margin-bottom: 6px; }
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
    .btn-red { background: #ef4444; color: #fff; }
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
    .toast { color: #34d399; font-size: 13px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>⚡ Automação Pix ➔ Carteira Cripto pelo WhatsApp</h1>
      <p>Configure sua conta abaixo, leia o QR Code do WhatsApp e receba pagamentos direto na sua carteira.</p>
    </header>

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
            <option value="depixapp">DePix App (Sem pedir CPF no chat - Rede Liquid)</option>
            <option value="hodle">Hodle (USDT / USDC - Base / Polygon)</option>
            <option value="noxpay">NoxPay CrossRamp (USDT / BTC)</option>
            <option value="mock">Modo Demonstração (Apenas teste sem dinheiro real)</option>
          </select>
        </label>
        <label>
          Chave de API da Plataforma (sk_live_... / API Key)
          <input id="apiKey" type="password" placeholder="Cole aqui a chave da sua conta..." />
        </label>
        <label>
          Endereço da Sua Carteira Cripto
          <input id="walletAddress" placeholder="Ex: lq1qq... ou 0x..." />
        </label>
        <label>
          Moeda / Rede da Carteira
          <div style="display:flex;gap:8px;">
            <input id="walletAsset" placeholder="DEPIX ou USDT" style="width:50%;" />
            <input id="walletNetwork" placeholder="LIQUID ou POLYGON" style="width:50%;" />
          </div>
        </label>
      </div>
      <div style="display:flex;align-items:center;gap:12px;">
        <button class="btn" onclick="saveAccount()">💾 Salvar Conta & Carteira</button>
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
            <select id="filterMode" onchange="saveWaFilter()">
              <option value="keyword_only" selected>🔒 Só responder quando falarem "Pix" ou "Pagar" (Não atrapalha conversas pessoais)</option>
              <option value="all">📢 Responder qualquer mensagem (Para chip exclusivo de vendas)</option>
            </select>
          </label>
          <label>
            Opcional: Restringir teste apenas a 1 telefone (ex: 5511999998888)
            <input id="allowedPhone" placeholder="Deixe vazio para atender qualquer cliente que pedir Pix" onchange="saveWaFilter()" />
          </label>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button class="btn" onclick="connectWa()">📲 Gerar QR Code do WhatsApp</button>
            <button class="btn btn-red" onclick="disconnectWa()">Desconectar WhatsApp</button>
          </div>
          <p id="waHint" style="font-size:13px;color:var(--muted);"></p>
        </div>
        <div id="qrBox" class="qr-box">Clique em<br/>"Gerar QR Code"<br/>ao lado</div>
      </div>
    </section>

    <!-- PASSO 3: PAGAMENTOS EM TEMPO REAL -->
    <section class="step-card">
      <div class="step-title">
        <h2>3️⃣ Chaves Pix Geradas & Pagamentos Confirmados</h2>
        <span style="font-size:12px;color:var(--muted);">Atualiza sozinho</span>
      </div>
      <div id="ordersList" style="display:flex;flex-direction:column;gap:10px;"></div>
    </section>
  </div>

  <script>
    const providerEl = document.getElementById('provider');
    const apiKeyEl = document.getElementById('apiKey');
    const walletAddressEl = document.getElementById('walletAddress');
    const walletAssetEl = document.getElementById('walletAsset');
    const walletNetworkEl = document.getElementById('walletNetwork');
    const accBadge = document.getElementById('accBadge');
    const saveMsg = document.getElementById('saveMsg');
    const waBadge = document.getElementById('waBadge');
    const qrBox = document.getElementById('qrBox');
    const waHint = document.getElementById('waHint');
    const filterMode = document.getElementById('filterMode');
    const allowedPhone = document.getElementById('allowedPhone');
    const ordersList = document.getElementById('ordersList');

    async function loadAccount() {
      const res = await fetch('/api/account');
      const acc = await res.json();
      providerEl.value = acc.provider;
      walletAddressEl.value = acc.walletAddress || '';
      walletAssetEl.value = acc.walletAsset || 'DEPIX';
      walletNetworkEl.value = acc.walletNetwork || 'LIQUID';
      if (acc.apiKeyPreview) {
        apiKeyEl.placeholder = 'Salva (' + acc.apiKeyPreview + ') - digite p/ trocar';
      }
      accBadge.textContent = acc.provider === 'mock' ? 'MODO DEMONSTRAÇÃO' : ('CONTA ATIVA: ' + acc.provider.toUpperCase());
    }

    async function saveAccount() {
      saveMsg.textContent = 'Salvando...';
      await fetch('/api/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: providerEl.value,
          apiKey: apiKeyEl.value,
          walletAddress: walletAddressEl.value,
          walletAsset: walletAssetEl.value,
          walletNetwork: walletNetworkEl.value
        })
      });
      apiKeyEl.value = '';
      saveMsg.textContent = '✅ Conta salva e ativa!';
      setTimeout(() => { saveMsg.textContent = ''; }, 3500);
      await loadAccount();
    }

    async function connectWa() {
      qrBox.innerHTML = 'Gerando QR Code...';
      await fetch('/api/whatsapp/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filterMode: filterMode.value,
          allowedTestPhone: allowedPhone.value
        })
      });
      await pollStatus();
    }

    async function saveWaFilter() {
      await fetch('/api/whatsapp/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filterMode: filterMode.value,
          allowedTestPhone: allowedPhone.value
        })
      });
    }

    async function disconnectWa() {
      await fetch('/api/whatsapp/disconnect', { method: 'POST' });
      await pollStatus();
    }

    async function simulatePay(id) {
      await fetch('/api/simulator/pay/' + encodeURIComponent(id), { method: 'POST' });
      await pollStatus();
    }

    async function pollStatus() {
      const [waRes, ordRes] = await Promise.all([
        fetch('/api/whatsapp/status'),
        fetch('/api/orders')
      ]);
      const wa = await waRes.json();
      const orders = await ordRes.json();

      waBadge.textContent = wa.state === 'CONNECTED' ? '🟢 WHATSAPP CONECTADO' : wa.state;
      if (wa.state === 'CONNECTED') {
        qrBox.innerHTML = '<div style="color:#34d399;font-weight:700;">🟢 Conectado!<br/>+' + (wa.connectedPhone || '') + '</div>';
        waHint.textContent = 'Tudo pronto! Basta alguém mandar "Me manda um Pix de 50" para esse WhatsApp.';
      } else if (wa.state === 'QR_READY' && wa.qrCodeDataUrl) {
        qrBox.innerHTML = '<img src="' + wa.qrCodeDataUrl + '" alt="QR WhatsApp" />';
        waHint.textContent = 'No celular: Abra o WhatsApp > Aparelhos Conectados > Conectar Aparelho e aponte para o QR ao lado.';
      } else if (wa.state === 'CONNECTING') {
        qrBox.innerHTML = 'Aguarde...';
      } else {
        qrBox.innerHTML = 'Clique em<br/>"Gerar QR Code"';
        waHint.textContent = wa.lastError || '';
      }

      ordersList.innerHTML = orders.length === 0
        ? '<p style="color:var(--muted);font-size:13.5px;">Nenhum Pix solicitado ainda. Assim que alguém pedir no WhatsApp, aparecerá aqui!</p>'
        : orders.map(o => {
            const brl = Number(o.amountBrl).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const simBtn = (o.status === 'PENDING' && o.provider === 'mock')
              ? '<button class="btn" style="padding:6px 12px;font-size:12px;" onclick="simulatePay(\\'' + o.id + '\\')">Simular Pagamento (Teste)</button>'
              : '';
            return '<div class="order-row">' +
              '<div><strong>' + brl + '</strong> <span style="color:var(--muted);font-size:13px;">(Cliente: +' + o.customerPhone + ')</span></div>' +
              '<div style="display:flex;align-items:center;gap:10px;">' +
                simBtn +
                '<span class="pill">' + o.status + '</span>' +
              '</div>' +
            '</div>';
          }).join('');
    }

    loadAccount();
    setInterval(pollStatus, 2000);
    pollStatus();
  </script>
</body>
</html>`;
}
