const $ = (sel) => document.querySelector(sel);
function on(id, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener("click", handler);
}
function val(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : "";
}

let toastTimer;
function toast(msg, isError = false) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = msg;
  el.className = `toast${isError ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "toast hidden"; }, 3000);
}

let extensionReady = false;
let createdMnemonic = null;
let currentStep = "welcome";

window.dwOnReady = function() {
  extensionReady = true;
  render();
};

async function rpc(method, params) {
  if (!window.ethereum) throw new Error("Extension not found");
  return window.ethereum.request({ method, params });
}

function starSvg() {
  return `<svg width="16" height="16" viewBox="0 0 24 24" fill="black" stroke="black" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;
}

function progressBar(step) {
  const order = { welcome: 0, choose: 1, "import-phrase": 1, "import-key": 1, backup: 2, done: 3 };
  const idx = order[step] ?? 0;
  let dots = "";
  for (let i = 0; i < 4; i++) {
    const cls = i < idx ? "done" : i === idx ? "active" : "";
    dots += `<div class="progress-dot ${cls}"></div>`;
  }
  return `<div class="progress">${dots}</div>`;
}

function goTo(step) {
  currentStep = step;
  render();
}

function render() {
  const app = $("#app");
  if (!app) return;
  const { html, bind } = renderStep(currentStep);
  app.innerHTML = html;
  if (bind) bind();
}

function renderStep(step) {
  switch (step) {
    case "welcome": return stepWelcome();
    case "choose": return stepChoose();
    case "import-phrase": return stepImportPhrase();
    case "import-key": return stepImportKey();
    case "backup": return stepBackup();
    case "done": return stepDone();
    default: return stepWelcome();
  }
}

function stepWelcome() {
  const statusCls = extensionReady ? "connected" : "disconnected";
  const statusText = extensionReady ? "Extension detected" : "Waiting for extension...";

  const installGuide = !extensionReady ? `
    <div class="install-guide mb-5">
      <div class="tag tag-muted rotate-n1 mb-4">
        <span class="text-lg tracking-tight">Firefox</span>
      </div>
      <ol class="steps-list">
        <li class="text-sm"><span class="step-num" style="background:var(--neo-accent)">1</span> Open about:debugging#/runtime/this-firefox</li>
        <li class="text-sm"><span class="step-num" style="background:var(--neo-secondary)">2</span> Click Load Temporary Add-on</li>
        <li class="text-sm"><span class="step-num" style="background:var(--neo-muted)">3</span> Select manifest.json inside dist_ext</li>
        <li class="text-sm"><span class="step-num" style="background:var(--neo-accent)">4</span> Refresh this page</li>
      </ol>
    </div>
  ` : "";

  return {
    html: `
      <div class="card">
        ${progressBar("welcome")}

        <div class="text-center mb-6">
          <div class="tag tag-accent rotate-n2 mb-4">
            <span class="text-2xl tracking-tight">DiceWallet</span>
          </div>
          <div class="stars mb-4">${starSvg()}${starSvg()}${starSvg()}</div>
          <p class="text-lg font-black uppercase tracking-wide mb-2">Welcome</p>
          <p class="text-sm opacity-70">Let's set up your first account.</p>
        </div>

        <div class="status">
          <div class="status-dot ${statusCls}"></div>
          <span>${statusText}</span>
        </div>

        ${installGuide}

        <div class="flex-col gap-3">
          <button id="btn-next" class="btn btn-primary" ${extensionReady ? "" : "disabled"}>Get Started</button>
          <a href="/admin" class="btn btn-outline mt-4" style="display:flex;align-items:center;justify-content:center;text-decoration:none;color:#000">Submit Flag</a>
        </div>
      </div>
    `,
    bind() {
      on("btn-next", async () => {
        try {
          const state = await rpc("wallet_getState");
          if (state.hasWallet) { goTo("done"); return; }
        } catch {}
        goTo("choose");
      });
    }
  };
}

function stepChoose() {
  return {
    html: `
      <div class="card">
        ${progressBar("choose")}

        <div class="tag tag-secondary rotate-1 mb-5">
          <span class="text-lg tracking-tight">Setup</span>
        </div>

        <p class="text-sm mb-5 opacity-70">Choose how you'd like to set up your wallet.</p>

        <div class="flex-col gap-3">
          <button id="btn-create" class="btn btn-primary">Create New Wallet</button>
          <button id="btn-import-phrase" class="btn btn-secondary">Import Recovery Phrase</button>
          <button id="btn-import-key" class="btn btn-outline">Import Private Key</button>
        </div>
      </div>
    `,
    bind() {
      on("btn-create", async () => {
        try {
          const result = await rpc("wallet_generate");
          createdMnemonic = result.mnemonic;
          goTo("backup");
        } catch (e) { toast(e.message, true); }
      });
      on("btn-import-phrase", () => goTo("import-phrase"));
      on("btn-import-key", () => goTo("import-key"));
    }
  };
}

function stepImportPhrase() {
  return {
    html: `
      <div class="card">
        ${progressBar("import-phrase")}

        <button id="btn-back" class="btn btn-outline back-btn">&larr; Back</button>

        <div class="tag tag-muted rotate-n1 mb-5">
          <span class="text-lg tracking-tight">Import Phrase</span>
        </div>

        <div class="mb-3">
          <span class="label">Account Name</span>
          <input id="import-name" class="input" type="text" placeholder="My Account" />
        </div>

        <div class="mb-4">
          <span class="label">Recovery Phrase (12 or 24 words)</span>
          <textarea id="import-phrase-input" class="textarea" rows="4" placeholder="abandon ability able about above absent ..."></textarea>
        </div>

        <button id="btn-import" class="btn btn-primary">Import Wallet</button>
      </div>
    `,
    bind() {
      on("btn-back", () => goTo("choose"));
      on("btn-import", async () => {
        const phrase = val("import-phrase-input");
        const name = val("import-name");
        if (!phrase) return toast("Enter a recovery phrase", true);
        try {
          await rpc("wallet_importMnemonic", [{ mnemonic: phrase, name: name || undefined }]);
          toast("Wallet imported!");
          goTo("done");
        } catch (e) { toast(e.message, true); }
      });
    }
  };
}

function stepImportKey() {
  return {
    html: `
      <div class="card">
        ${progressBar("import-key")}

        <button id="btn-back" class="btn btn-outline back-btn">&larr; Back</button>

        <div class="tag tag-accent rotate-1 mb-5">
          <span class="text-lg tracking-tight">Import Key</span>
        </div>

        <div class="mb-3">
          <span class="label">Account Name</span>
          <input id="import-name" class="input" type="text" placeholder="My Account" />
        </div>

        <div class="mb-4">
          <span class="label">Private Key (hex)</span>
          <input id="import-key-input" class="input" type="password" placeholder="0x..." />
        </div>

        <button id="btn-import" class="btn btn-primary">Import Wallet</button>
      </div>
    `,
    bind() {
      on("btn-back", () => goTo("choose"));
      on("btn-import", async () => {
        const key = val("import-key-input");
        const name = val("import-name");
        if (!key) return toast("Enter a private key", true);
        try {
          await rpc("wallet_importPrivateKey", [{ privateKey: key, name: name || undefined }]);
          toast("Wallet imported!");
          goTo("done");
        } catch (e) { toast(e.message, true); }
      });
    }
  };
}

function stepBackup() {
  const words = (createdMnemonic || "").split(" ");
  const grid = words.map((w, i) =>
    `<div class="word-cell">${i + 1}. ${w}</div>`
  ).join("");

  return {
    html: `
      <div class="card">
        ${progressBar("backup")}

        <div class="warning mb-4">
          <span class="warning-icon">!</span>
          <span>Save these words — anyone with this phrase can access your funds</span>
        </div>

        <div class="word-grid-wrap mb-4">
          <div class="word-grid">${grid}</div>
        </div>

        <button id="btn-copy" class="btn btn-outline mb-3">Copy Phrase</button>
        <button id="btn-done" class="btn btn-primary">I've Saved My Phrase &rarr;</button>
      </div>
    `,
    bind() {
      on("btn-copy", () => {
        if (createdMnemonic) {
          navigator.clipboard.writeText(createdMnemonic);
          toast("Copied to clipboard");
        }
      });
      on("btn-done", () => {
        createdMnemonic = null;
        goTo("done");
      });
    }
  };
}

function stepDone() {
  return {
    html: `
      <div class="card text-center">
        ${progressBar("done")}

        <div class="mb-5">
          <div class="tag tag-secondary rotate-n2 mb-4">
            <span class="text-2xl tracking-tight">All Set!</span>
          </div>
          <div class="stars mb-4">${starSvg()}${starSvg()}${starSvg()}${starSvg()}${starSvg()}</div>
        </div>

        <p class="text-sm mb-3 font-black uppercase tracking-wide">Your wallet is ready</p>
        <p class="text-sm opacity-70 mb-6">Click the DiceWallet icon in your browser toolbar to start using your wallet.</p>

        <div class="next-steps mb-5">
          <p class="text-xs opacity-50 uppercase tracking-wide">Next steps</p>
          <ul class="steps-list">
            <li class="text-sm">
              <span class="step-num" style="background:var(--neo-accent)">1</span>
              Open the extension popup
            </li>
            <li class="text-sm">
              <span class="step-num" style="background:var(--neo-secondary)">2</span>
              Fund your wallet with ETH
            </li>
            <li class="text-sm">
              <span class="step-num" style="background:var(--neo-muted)">3</span>
              Connect to dApps
            </li>
          </ul>
        </div>

        <button id="btn-new" class="btn btn-outline">Set Up Another Account</button>
      </div>
    `,
    bind() {
      on("btn-new", () => goTo("choose"));
    }
  };
}

document.addEventListener("DOMContentLoaded", render);
