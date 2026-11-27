const { invoke } = window.__TAURI__.core;
const win = window.__TAURI__.window.getCurrentWindow();
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];

const IDLE_LOCK_MS = 10 * 60_000;
const CONFLICT = "O cofre foi alterado em outro dispositivo."; // = github::CONFLICT
const NEEDS_VAULT_PASSWORD = "Este cofre tem uma senha própria."; // = crypto::NEEDS_VAULT_PASSWORD
const VAULT_NAME = /^[\p{L}\p{N} _-]{1,48}$/u;               // = valid_name() in main.rs
const entryKey = (e) => JSON.stringify([e.name, e.url, e.username, e.email, e.password, e.notes, e.tag]);
const mergeKey = (e) => entryKey(e) + (e.favorite ? "★" : ""); // a merge must keep favorite-only changes too

const S = {
  repo: "", vaults: [], current: null, entries: [],
  dirty: false, version: 0,      // version bumps on every change, so a save only clears what it sent
  sel: -1, visible: [],          // selected entry index; indices currently listed
  filter: { type: "all", tag: "" },
  editing: null, touched: false, // editor state: { index } (-1 = new)
  revealed: false, busy: 0,
  locked: new Set(),             // vaults known to have their own password (shown with a lock)
};

// ---------- DOM helpers (user data only ever goes through textContent) ----------
const SVGNS = "http://www.w3.org/2000/svg";
function icon(id, cls = "") {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", `ic ${cls}`);
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", `#i-${id}`);
  s.append(u);
  return s;
}
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "text") n.textContent = v;
    else if (k === "class") n.className = v;
    else if (k.startsWith("on")) n[k] = v;
    else n.setAttribute(k, v);
  }
  n.append(...kids.filter((k) => k != null && k !== false));
  return n;
}
function iconBtn(id, title, onclick, cls = "") {
  return el("button", { type: "button", class: `icon-btn ${cls}`, title, "aria-label": title, onclick: (ev) => { ev.stopPropagation(); onclick(ev); } }, icon(id));
}
function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.codePointAt(0)) | 0; return Math.abs(h); }
function hue(s) { return hash(s.toLowerCase()) % 360; }
function avatar(name, cls = "") {
  const letter = (name.match(/[\p{L}\p{N}]/u) || ["?"])[0];
  const h = hue(name || "?");
  const a = el("div", { class: `avatar ${cls}`, text: letter });
  a.style.background = `linear-gradient(140deg, hsl(${h} 62% 58%), hsl(${(h + 28) % 360} 58% 44%))`;
  return a;
}
function swatch(tag) { const s = el("span", { class: "swatch" }); s.style.background = `hsl(${hue(tag)} 65% 60%)`; return s; }
function host(url) {
  if (!url) return "";
  try { return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, ""); } catch { return url; }
}
// Also covers buttons: Enter/Delete on a focused button must activate it, not trigger a list shortcut.
const typing = () => /^(INPUT|TEXTAREA|SELECT|BUTTON|A)$/.test(document.activeElement?.tagName);

// ---------- feedback ----------
function toast(msg, err = false) {
  const t = el("div", { class: `toast${err ? " err" : ""}` }, icon(err ? "alert" : "check"), el("span", { text: String(msg) }));
  $("#toasts").append(t);
  setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 200); }, err ? 6000 : 2600);
}

async function call(cmd, args) {
  S.busy++;
  document.body.classList.add("busy");
  try { return await invoke(cmd, args); }
  finally { if (--S.busy === 0) document.body.classList.remove("busy"); }
}

let pendingModal = null; // resolver of the dialog currently open, so a newer one cancels it instead of orphaning it

/** Promise-based dialog. Returns true / the typed text, or null if cancelled. */
function modal({ title, message = "", input = null, ok = "OK", cancel = "Cancelar", danger = false, validate = null }) {
  const d = $("#modal"), inp = $("#modal-input"), err = $("#modal-err"), okBtn = $("#modal-ok");
  if (pendingModal) { pendingModal(null); pendingModal = null; }
  $("#modal-title").textContent = title;
  $("#modal-msg").textContent = message;
  $("#modal-ic").className = `modal-ic${danger ? " danger" : ""}`;
  $("#modal-input-wrap").classList.toggle("hidden", !input);
  inp.type = input?.type || "text";
  inp.placeholder = input?.placeholder || "";
  inp.value = input?.value || "";
  err.textContent = "";
  okBtn.textContent = ok;
  okBtn.className = `btn ${danger ? "danger" : "primary"}`;
  $("#modal-cancel").classList.toggle("hidden", cancel === null);
  $("#modal-cancel").textContent = cancel || "";
  if (!d.open) d.showModal();
  (input ? inp : okBtn).focus();
  return new Promise((resolve) => {
    pendingModal = resolve;
    const done = (v) => { pendingModal = null; d.close(); inp.value = ""; resolve(v); }; // don't keep typed secrets in the DOM
    $("#modal-form").onsubmit = async (ev) => {
      ev.preventDefault();
      const v = input ? inp.value : true;
      const problem = validate && (await validate(v));
      if (problem) { err.textContent = problem; inp.focus(); return; }
      done(v);
    };
    $("#modal-cancel").onclick = () => done(null);
    d.oncancel = (ev) => { ev.preventDefault(); done(null); }; // Esc
  });
}

// Unsaved = vault changes not on GitHub yet, or an item open in the editor with changes not "Concluído".
const hasUnsaved = () => S.dirty || !!(S.editing && S.touched);

/** Asks before throwing away unsaved work; on yes (or nothing unsaved) also closes the editor. */
async function confirmDiscard() {
  if (hasUnsaved()) {
    const ok = await modal({
      title: "Descartar alterações?", ok: "Descartar", danger: true,
      message: S.dirty ? `O cofre "${S.current}" tem alterações que ainda não foram salvas no GitHub.` : "O item em edição ainda não foi concluído.",
    });
    if (!ok) return false;
  }
  if (S.editing) closeEditor();
  return true;
}

async function copy(text, what, btn) {
  if (!text) return toast(`${what} vazio.`, true);
  try {
    await invoke("copy_secret", { text }); // Rust clears it after 30 s, even with the window in the background
    toast(`${what} copiado · limpo em 30 s`);
    if (btn) {
      btn.classList.add("copied");
      btn.querySelector("use").setAttribute("href", "#i-check");
      setTimeout(() => { btn.classList.remove("copied"); btn.querySelector("use").setAttribute("href", "#i-copy"); }, 1200);
    }
  } catch (e) { toast(e, true); }
}

// ---------- window chrome ----------
const winActions = { min: () => win.minimize(), max: () => win.toggleMaximize(), close: () => win.close() };
$$("[data-win]").forEach((b) => (b.onclick = () => winActions[b.dataset.win]()));
async function syncMaxIcon() {
  const max = await win.isMaximized();
  const b = $('[data-win="max"]');
  b.querySelector("use").setAttribute("href", max ? "#i-restore" : "#i-max");
  b.title = max ? "Restaurar" : "Maximizar";
}
win.onResized(syncMaxIcon);

// Closing with unsaved changes asks first (beforeunload doesn't fire for native window close).
win.onCloseRequested(async (ev) => {
  if (hasUnsaved() && !(await modal({ title: "Fechar sem salvar?", message: "Há alterações não salvas. Elas serão perdidas.", ok: "Fechar mesmo assim", danger: true }))) ev.preventDefault();
});

// set_layout can't resize a minimized window; redo it when the window comes back.
let pendingLayout = null;
async function layout(main) {
  pendingLayout = (await invoke("set_layout", { main })) ? null : main;
}
win.onFocusChanged(({ payload: focused }) => { if (focused && pendingLayout !== null) layout(pendingLayout); });

// Show/hide buttons for password inputs.
$$("[data-reveal]").forEach((b) => (b.onclick = () => {
  const inp = b.parentElement.querySelector("input");
  const show = inp.type === "password";
  inp.type = show ? "text" : "password";
  b.querySelector("use").setAttribute("href", show ? "#i-eye-off" : "#i-eye");
}));

// ---------- login ----------
async function initLogin() {
  const saved = await invoke("saved_login");
  const compact = !!(saved.repo && saved.has_token);
  $("#repo").value = saved.repo;
  $("#account-repo").textContent = saved.repo;
  $("#account-summary").classList.toggle("hidden", !compact);
  $("#account-fields").classList.toggle("hidden", compact);
  $("#token").value = "";
  $("#token").placeholder = saved.has_token ? "Token salvo no Windows (deixe vazio)" : "github_pat_…";
  $("#forget").classList.toggle("hidden", !saved.has_token);
  $("#master").value = "";
  $("#master").type = "password";
  (saved.repo ? $("#master") : $("#repo")).focus();
}

$("#account-change").onclick = () => {
  $("#account-summary").classList.add("hidden");
  $("#account-fields").classList.remove("hidden");
  $("#repo").focus();
};

$("#forget").onclick = async () => {
  await invoke("forget_token");
  $("#forget").classList.add("hidden");
  $("#token").placeholder = "github_pat_…";
  toast("Token removido do Gerenciador de Credenciais.");
};

["keydown", "keyup"].forEach((t) => $("#master").addEventListener(t, (ev) => {
  $("#caps").classList.toggle("hidden", !ev.getModifierState?.("CapsLock"));
}));

$("#login-form").onsubmit = async (ev) => {
  ev.preventDefault();
  const msg = $("#login-msg"), btn = $("#connect");
  msg.textContent = "";
  if (!$("#repo").value.trim()) return (msg.textContent = "Informe o repositório (usuario/repositorio).");
  if (!$("#master").value) return (msg.textContent = "Digite a senha mestra."), $("#master").focus();
  btn.classList.add("loading");
  btn.disabled = true;
  $(".btn-label", btn).textContent = "Derivando chave…";
  try {
    const res = await call("connect", { token: $("#token").value, repo: $("#repo").value, master: $("#master").value, remember: $("#remember").checked });
    $("#master").value = $("#token").value = "";
    S.repo = $("#repo").value.trim();
    S.vaults = res.vaults;
    if (res.setup) showSetup(res);
    else await enterApp(res);
  } catch (e) {
    msg.textContent = e;
    $("#master").select();
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
    $(".btn-label", btn).textContent = "Desbloquear";
  }
};

// ---------- setup of a new (empty) repo ----------
function showSetup(res) {
  $("#login").classList.add("hidden");
  $("#setup").classList.remove("hidden");
  $("#setup-repo").textContent = S.repo;
  const n = res.other_files;
  $("#setup-other").textContent = n ? `O repositório já tem ${n} ${n === 1 ? "arquivo" : "arquivos"} que não ${n === 1 ? "é" : "são"} do URPM. Nada disso é alterado.` : "";
  $("#setup-other").classList.toggle("hidden", !n);
  $("#setup-master").value = $("#setup-confirm").value = "";
  $("#setup-vault").value = "Pessoal";
  $("#setup-msg").textContent = "";
  paintStrength($("#setup-strength"), "");
  S.setupPrivate = res.private;
  if (!res.private) $("#setup-msg").textContent = "Atenção: este repositório é PÚBLICO. Os dados ficam cifrados, mas prefira um privado.";
  $("#setup-master").focus();
}

$("#setup-master").addEventListener("input", () => paintStrength($("#setup-strength"), $("#setup-master").value));

$("#setup-back").onclick = async () => {
  if ($("#setup-ok").disabled) return; // setup in progress
  $("#setup-master").value = $("#setup-confirm").value = "";
  await invoke("lock");
  $("#setup").classList.add("hidden");
  $("#login").classList.remove("hidden");
  await initLogin();
};

$("#setup-form").onsubmit = async (ev) => {
  ev.preventDefault();
  const msg = $("#setup-msg"), btn = $("#setup-ok");
  const master = $("#setup-master").value, vault = $("#setup-vault").value.trim();
  msg.textContent = "";
  if ([...master].length < 10) return (msg.textContent = "Use pelo menos 10 caracteres na senha mestra."), $("#setup-master").focus();
  if (master !== $("#setup-confirm").value) return (msg.textContent = "As senhas não coincidem."), $("#setup-confirm").focus();
  if (!VAULT_NAME.test(vault)) return (msg.textContent = "Nome do cofre: até 48 letras, números, espaço, '-' ou '_'."), $("#setup-vault").focus();
  btn.classList.add("loading");
  btn.disabled = true;
  try {
    const done = await call("setup_repo", { master, vault, vaultPassword: null });
    S.vaults = done.vaults;
    $("#setup-master").value = $("#setup-confirm").value = "";
    $("#setup").classList.add("hidden");
    await enterApp({ private: S.setupPrivate });
    if (done.warning) return toast(`${done.warning} Crie-o pelo botão + na lateral.`, true);
    await openVault(vault); // just created, its key is cached: opens without asking anything
    toast("Repositório configurado. Bem-vindo!");
  } catch (e) {
    msg.textContent = e;
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
  }
};

async function enterApp(res) {
  document.body.className = "mode-app";
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#repo-name").textContent = S.repo;
  await layout(true);
  syncMaxIcon();
  showVault(); // no vault opens by itself: the user picks one
  if (!res.private) toast("Atenção: o repositório é PÚBLICO. Os dados estão cifrados, mas prefira um repositório privado.", true);
}

async function lock(reason) {
  await invoke("lock");
  if (pendingModal) { pendingModal(null); pendingModal = null; }
  if ($("#modal").open) $("#modal").close();
  if (pendingVaultDialog) { pendingVaultDialog(null); pendingVaultDialog = null; }
  if ($("#vault-dialog").open) $("#vault-dialog").close();
  $("#setup").classList.add("hidden");
  $("#modal-input").value = $("#setup-master").value = $("#setup-confirm").value = "";
  $("#vault-form").reset();
  S.locked.clear();
  Object.assign(S, { vaults: [], current: null, entries: [], visible: [], sel: -1, editing: null, touched: false, revealed: false, filter: { type: "all", tag: "" } });
  setDirty(false);
  // Don't leave decrypted data sitting in hidden DOM nodes.
  $("#rows").replaceChildren();
  $("#detail").replaceChildren();
  form.reset();
  $("#editor").classList.add("hidden");
  $("#search").value = "";
  document.body.className = "mode-login";
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#tb-title").textContent = "";
  await layout(false);
  await initLogin();
  if (reason) $("#login-msg").textContent = reason;
}

$("#lock").onclick = async () => { if (await confirmDiscard()) lock(); };

let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (document.body.classList.contains("mode-app")) lock(`Bloqueado por inatividade${S.dirty ? " (alterações não salvas foram descartadas)" : ""}.`);
  }, IDLE_LOCK_MS);
}
["mousemove", "keydown", "mousedown", "wheel"].forEach((e) => addEventListener(e, resetIdle, { passive: true }));
resetIdle();

// ---------- vaults ----------
function renderVaults() {
  $("#vaults").replaceChildren(...S.vaults.map((name) =>
    el("button", { class: name === S.current ? "active" : "", title: name, onclick: () => openVault(name) },
      icon("folder"), el("span", { class: "name", text: name }), S.locked.has(name) ? icon("lock", "lock") : null)));
}

function showVault() {
  const open = !!S.current;
  $("#no-vault").classList.toggle("hidden", open);
  $("#list-wrap").classList.toggle("hidden", !open);
  $("#filters-block").classList.toggle("hidden", !open);
  $("#tb-title").textContent = S.current || "";
  $("#vault-title").textContent = S.current || "";
  renderVaults();
  renderFilters();
  renderList();
  renderDetail();
}

/** Loads a vault's entries, asking for its own password when needed (also when it was re-keyed on
 *  another device while open). Returns null if the user cancels or it fails (already reported). */
async function fetchVault(name) {
  try {
    return await call("open_vault", { name, password: null });
  } catch (e) {
    if (String(e) !== NEEDS_VAULT_PASSWORD) { toast(e, true); return null; }
  }
  S.locked.add(name);
  renderVaults();
  let entries = null;
  const ok = await modal({
    title: `Cofre "${name}"`, message: "Este cofre tem uma senha própria, além da senha mestra.",
    input: { type: "password", placeholder: "Senha do cofre" }, ok: "Abrir",
    validate: async (pw) => {
      if (!pw) return "Digite a senha do cofre.";
      try { entries = await call("open_vault", { name, password: pw }); } catch (err) { return String(err); }
    },
  });
  return ok ? entries : null;
}

async function openVault(name) {
  if (name === S.current || !(await confirmDiscard())) return;
  const entries = await fetchVault(name);
  if (!entries) return;
  S.entries = entries;
  Object.assign(S, { current: name, sel: -1, filter: { type: "all", tag: "" } });
  $("#search").value = "";
  setDirty(false);
  showVault();
}

let pendingVaultDialog = null;
/** Create-vault / vault-password dialog. Resolves { name, password|null } or null if cancelled. */
function vaultDialog({ mode, name = "" }) {
  const d = $("#vault-dialog"), f = $("#vault-form"), create = mode === "create";
  const wasLocked = !create && S.locked.has(name);
  f.reset();
  $("#vd-err").textContent = "";
  $("#vd-title").textContent = create ? "Novo cofre" : `Senha do cofre "${name}"`;
  $("#vd-msg").textContent = create ? "Separe suas senhas por contexto: pessoal, trabalho, família…"
    : wasLocked ? "Este cofre tem uma senha própria. Digite uma nova para trocá-la, ou desligue a proteção." : "Hoje este cofre abre só com a senha mestra.";
  $("#vd-name-field").classList.toggle("hidden", !create);
  f.elements.protect.checked = wasLocked;
  $("#vd-pass").classList.toggle("hidden", !wasLocked);
  $("#vd-ok").textContent = create ? "Criar cofre" : "Salvar";
  d.showModal();
  (create ? f.elements.name : f.elements.protect).focus();
  return new Promise((resolve) => {
    pendingVaultDialog = resolve;
    const done = (v) => { pendingVaultDialog = null; d.close(); f.reset(); resolve(v); };
    const fail = (msg, field) => { $("#vd-err").textContent = msg; field?.focus(); };
    f.onsubmit = (ev) => {
      ev.preventDefault();
      const n = f.elements.name.value.trim(), protect = f.elements.protect.checked, pw = f.elements.password.value;
      if (create && !VAULT_NAME.test(n)) return fail("Use até 48 letras, números, espaço, '-' ou '_'.", f.elements.name);
      if (create && S.vaults.some((x) => x.toLowerCase() === n.toLowerCase())) return fail("Já existe um cofre com esse nome.", f.elements.name);
      if (!create && protect === wasLocked && !pw) return done(null); // nothing changed
      if (protect && [...pw].length < 8) return fail("Use pelo menos 8 caracteres na senha do cofre.", f.elements.password);
      if (protect && pw !== f.elements.confirm.value) return fail("As senhas do cofre não coincidem.", f.elements.confirm);
      done({ name: n, password: protect ? pw : null });
    };
    $("#vd-cancel").onclick = () => done(null);
    d.oncancel = (ev) => { ev.preventDefault(); done(null); };
  });
}
$("#vault-form").elements.protect.onchange = (ev) => {
  $("#vd-pass").classList.toggle("hidden", !ev.target.checked);
  if (ev.target.checked) $("#vault-form").elements.password.focus();
};

async function newVault() {
  if (!(await confirmDiscard())) return;
  const r = await vaultDialog({ mode: "create" });
  if (!r) return;
  try {
    await call("create_vault", { name: r.name, password: r.password });
    if (r.password) S.locked.add(r.name); else S.locked.delete(r.name);
    S.vaults = await call("list_vaults");
    // The user already agreed to discard the previous vault: leave it now, so a failed open below isn't left half-shown.
    Object.assign(S, { current: null, entries: [], sel: -1 });
    setDirty(false);
    showVault();
    await openVault(r.name); // key is cached: no password prompt right after creating
    toast(`Cofre "${r.name}" criado.`);
  } catch (e) { toast(e, true); }
}

async function vaultPassword() {
  if (S.editing) { form.requestSubmit(); if (S.editing) return; }
  if (S.dirty) return toast("Salve o cofre antes de alterar a senha dele.", true);
  const name = S.current;
  const r = await vaultDialog({ mode: "password", name });
  if (!r) return;
  try {
    await call("set_vault_password", { name, password: r.password, entries: S.entries });
    if (r.password) S.locked.add(name); else S.locked.delete(name);
    renderVaults();
    toast(r.password ? "Senha do cofre definida." : "Senha do cofre removida.");
  } catch (e) { toast(e, true); }
}
$("#new-vault").onclick = newVault;
$("#empty-new-vault").onclick = newVault;

async function deleteVault() {
  const name = S.current;
  const typed = await modal({
    title: `Apagar o cofre "${name}"?`, danger: true, ok: "Apagar definitivamente",
    message: `Os ${S.entries.length} itens serão removidos do GitHub (ficam só no histórico do repositório). Exporte antes se quiser uma cópia.\n\nDigite o nome do cofre para confirmar:`,
    input: { placeholder: name }, validate: (v) => (v === name ? null : "O nome não confere."),
  });
  if (typed === null) return;
  try {
    await call("delete_vault", { name });
    S.vaults = S.vaults.filter((v) => v !== name);
    S.locked.delete(name);
    Object.assign(S, { current: null, entries: [], sel: -1, editing: null });
    $("#editor").classList.add("hidden");
    setDirty(false);
    showVault();
    toast("Cofre apagado.");
  } catch (e) { toast(e, true); }
}

// ---------- dirty / save ----------
function setDirty(d) {
  if (d) S.version++;
  S.dirty = d;
  $("#unsaved").classList.toggle("hidden", !d);
}

async function save() {
  // An item still open in the editor is committed first (a merge below replaces S.entries, so no stale editor index may survive).
  if (S.editing) { form.requestSubmit(); if (S.editing) return; }
  if (!S.current || !S.dirty) return;
  const sent = S.version;
  try {
    await call("save_vault", { name: S.current, entries: S.entries });
    toast("Salvo no GitHub.");
  } catch (e) {
    if (String(e) !== CONFLICT) return toast(e, true);
    const merge = await modal({
      title: "Cofre alterado em outro dispositivo", ok: "Mesclar e salvar",
      message: "Nada se perde: os itens que só existem aqui são acrescentados à versão do GitHub. Itens excluídos aqui podem reaparecer e itens editados podem ficar duplicados.",
    });
    if (!merge) return;
    try {
      const remote = await fetchVault(S.current); // also refreshes the sha (and asks for a new vault password if it changed)
      if (!remote) return;
      const seen = new Set(remote.map(mergeKey));
      const added = S.entries.filter((x) => !seen.has(mergeKey(x)));
      S.entries = remote.concat(added);
      S.sel = -1;
      await call("save_vault", { name: S.current, entries: S.entries });
      showVault();
      toast(`Mesclado e salvo (${added.length} ${added.length === 1 ? "item acrescentado" : "itens acrescentados"}).`);
    } catch (e2) { return toast(e2, true); }
  }
  if (S.version === sent) setDirty(false);
}
$("#save").onclick = save;

$("#discard").onclick = async () => {
  if (!(await modal({ title: "Descartar alterações?", message: "O cofre volta para a última versão salva no GitHub.", ok: "Descartar", danger: true }))) return;
  try {
    const entries = await fetchVault(S.current);
    if (!entries) return;
    S.entries = entries;
    S.sel = -1;
    S.editing = null;
    $("#editor").classList.add("hidden");
    setDirty(false);
    showVault();
  } catch (e) { toast(e, true); }
};

// ---------- filters & list ----------
function renderFilters() {
  if (!S.current) return $("#filters").replaceChildren();
  const tags = [...new Set(S.entries.map((e) => e.tag).filter(Boolean))].sort((a, b) => a.localeCompare(b, "pt-BR"));
  if (S.filter.type === "tag" && !tags.includes(S.filter.tag)) S.filter = { type: "all", tag: "" };
  const f = S.filter;
  const btn = (active, ico, label, count, onclick) =>
    el("button", { class: active ? "active" : "", onclick }, ico, el("span", { class: "name", text: label }), el("span", { class: "count", text: String(count) }));
  const pick = (filter) => () => { S.filter = filter; renderFilters(); renderList(); };
  $("#filters").replaceChildren(
    btn(f.type === "all", icon("layers"), "Todos os itens", S.entries.length, pick({ type: "all", tag: "" })),
    btn(f.type === "fav", icon("star", "fav"), "Favoritos", S.entries.filter((e) => e.favorite).length, pick({ type: "fav", tag: "" })),
    ...tags.map((t) => btn(f.type === "tag" && f.tag === t, swatch(t), t, S.entries.filter((e) => e.tag === t).length, pick({ type: "tag", tag: t }))),
  );
  $("#tag-list").replaceChildren(...tags.map((t) => el("option", { value: t })));
}

function renderList() {
  if (!S.current) return;
  const q = $("#search").value.trim().toLowerCase();
  const f = S.filter;
  const rows = S.entries
    .map((e, i) => [e, i])
    .filter(([e]) => (f.type === "fav" ? e.favorite : f.type === "tag" ? e.tag === f.tag : true))
    .filter(([e]) => !q || [e.name, e.url, e.username, e.email, e.notes, e.tag].join("\n").toLowerCase().includes(q))
    .sort(([a], [b]) => (b.favorite - a.favorite) || a.name.localeCompare(b.name, "pt-BR", { sensitivity: "base" }));
  S.visible = rows.map(([, i]) => i);
  const n = S.entries.length;
  $("#vault-count").textContent = `${n} ${n === 1 ? "item" : "itens"}`;
  $("#no-rows").classList.toggle("hidden", rows.length > 0);
  $("#no-rows-msg").textContent = n === 0 ? 'Este cofre está vazio. Clique em "Novo" ou importe um CSV pelo menu ⋯.' : "Nada encontrado com esses filtros.";
  $("#rows").replaceChildren(...rows.map(([e, i]) =>
    el("div", { class: `item${i === S.sel ? " selected" : ""}`, role: "option", "data-i": i, onclick: () => select(i), ondblclick: () => openEditor(i) },
      avatar(e.name),
      el("div", { class: "txt" }, el("div", { class: "t1", text: e.name || "(sem nome)" }), el("div", { class: "t2", text: e.username || e.email || host(e.url) || "—" })),
      e.favorite ? icon("star", "star") : null,
      el("div", { class: "quick" },
        iconBtn("copy", "Copiar usuário", () => copy(e.username || e.email, "Usuário")),
        iconBtn("key", "Copiar senha", () => copy(e.password, "Senha"))),
    )));
}

$("#search").addEventListener("input", renderList);

async function select(i, scroll = false) {
  if (i === S.sel && !S.editing) return;
  if (S.editing && !(await leaveEditor())) return;
  S.sel = i;
  S.revealed = false;
  $$(".item", $("#rows")).forEach((n) => n.classList.toggle("selected", +n.dataset.i === i));
  if (scroll) $(`.item[data-i="${i}"]`)?.scrollIntoView({ block: "nearest" });
  renderDetail();
}

// ---------- detail ----------
function frow(label, value, { secret = false, acts = [], extra = null, cls = "" } = {}) {
  return el("div", { class: `frow ${cls}` },
    el("div", { class: "fl" }, el("div", { class: "label", text: label }), el("div", { class: `value${secret ? " secret" : ""}`, text: value }), extra),
    el("div", { class: "acts" }, ...acts));
}

function renderDetail() {
  if (S.editing) return;
  const e = S.entries[S.sel];
  $("#detail-empty").classList.toggle("hidden", !!e);
  $("#detail").classList.toggle("hidden", !e);
  if (!e) return;

  const fav = iconBtn("star", e.favorite ? "Remover dos favoritos" : "Favoritar", () => {
    e.favorite = !e.favorite; setDirty(true); renderFilters(); renderList(); renderDetail();
  }, e.favorite ? "on" : "");
  const head = el("div", { class: "detail-head" },
    avatar(e.name, "lg"),
    el("div", { class: "grow" }, el("h2", { text: e.name || "(sem nome)" }), e.url ? el("div", { class: "sub", text: host(e.url) }) : null),
    fav,
    el("button", { type: "button", class: "btn sm", onclick: () => openEditor(S.sel) }, icon("edit"), "Editar"),
    iconBtn("trash", "Excluir item", deleteEntry),
  );

  const copyBtn = (text, what) => { const b = iconBtn("copy", `Copiar ${what.toLowerCase()}`, () => copy(text, what, b)); return b; };
  const rows = [];
  if (e.username) rows.push(frow("Usuário", e.username, { acts: [copyBtn(e.username, "Usuário")] }));
  if (e.email) rows.push(frow("E-mail", e.email, { acts: [copyBtn(e.email, "E-mail")] }));
  const masked = "•".repeat(Math.min(Math.max(e.password.length, 8), 18));
  const reveal = iconBtn(S.revealed ? "eye-off" : "eye", S.revealed ? "Ocultar" : "Mostrar", () => { S.revealed = !S.revealed; renderDetail(); });
  rows.push(frow("Senha", e.password ? (S.revealed ? e.password : masked) : "—", {
    secret: true, acts: e.password ? [reveal, copyBtn(e.password, "Senha")] : [],
    extra: e.password ? strengthEl(e.password) : null,
  }));
  if (e.url) rows.push(frow("Site", e.url, { acts: [iconBtn("external", "Abrir no navegador", () => invoke("open_url", { url: e.url }).catch((err) => toast(err, true))), copyBtn(e.url, "URL")] }));

  const meta = [];
  if (e.tag) meta.push(frow("Tag", "", { extra: el("span", { class: "chip" }, swatch(e.tag), e.tag) }));
  if (e.notes) meta.push(frow("Notas", e.notes, { cls: "notes", acts: [copyBtn(e.notes, "Notas")] }));

  $("#detail").replaceChildren(head, el("div", { class: "card" }, ...rows), meta.length ? el("div", { class: "card" }, ...meta) : null);
}

async function deleteEntry() {
  const e = S.entries[S.sel];
  if (!e || !(await modal({ title: `Excluir "${e.name}"?`, message: "O item sai deste cofre quando você salvar.", ok: "Excluir", danger: true }))) return;
  S.entries.splice(S.sel, 1);
  S.sel = -1;
  setDirty(true);
  renderFilters(); renderList(); renderDetail();
}

// ---------- password strength & generator ----------
function strength(pw) {
  if (!pw) return { score: 0, label: "" };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z\d]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool || 1);
  if (/^(.)\1*$/.test(pw)) bits = 0;
  const lv = bits < 28 ? 1 : bits < 36 ? 2 : bits < 60 ? 3 : bits < 80 ? 4 : 5;
  return { score: lv, label: ["", "Muito fraca", "Fraca", "Razoável", "Forte", "Excelente"][lv] };
}
const STRENGTH_COLORS = ["", "var(--danger)", "var(--danger)", "var(--warn)", "#7bd389", "var(--ok)"];
function paintStrength(box, pw) {
  const { score, label } = strength(pw);
  box.querySelector("i").style.width = `${score * 20}%`;
  box.querySelector("i").style.background = STRENGTH_COLORS[score];
  box.querySelector("span").textContent = label;
}
function strengthEl(pw) {
  const box = el("div", { class: "strength" }, el("div", { class: "bar" }, el("i")), el("span"));
  paintStrength(box, pw);
  return box;
}

function generatePassword() {
  const ambig = $("#gen-ambig").checked;
  const strip = (s) => (ambig ? s.replace(/[Il1O0o]/g, "") : s);
  const sets = [strip("abcdefghijklmnopqrstuvwxyz")];
  if ($("#gen-upper").checked) sets.push(strip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
  if ($("#gen-digits").checked) sets.push(strip("0123456789"));
  if ($("#gen-symbols").checked) sets.push("!@#$%&*-_=+?");
  const pool = sets.join("");
  const len = +$("#gen-len").value;
  const buf = new Uint32Array(1);
  const limit = 2 ** 32 - (2 ** 32 % pool.length); // rejection sampling: no modulo bias
  for (;;) {
    let out = "";
    while (out.length < len) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) out += pool[buf[0] % pool.length];
    }
    if (sets.every((s) => [...s].some((c) => out.includes(c)))) return out; // at least one of each chosen kind
  }
}

function applyGenerated() {
  const p = $("#editor").elements.password;
  p.value = generatePassword();
  p.type = "text";
  $('[data-reveal="password"] use').setAttribute("href", "#i-eye-off");
  paintStrength($("#strength"), p.value);
  S.touched = true;
}
$("#gen-toggle").onclick = () => {
  const g = $("#generator");
  g.classList.toggle("hidden");
  if (!g.classList.contains("hidden") && !$("#editor").elements.password.value) applyGenerated();
};
$("#gen-again").onclick = applyGenerated;
$("#gen-len").oninput = () => { $("#gen-len-label").textContent = `${$("#gen-len").value} caracteres`; applyGenerated(); };
$$("#generator input[type=checkbox]").forEach((c) => (c.onchange = applyGenerated));

// ---------- editor ----------
const form = $("#editor");
const FIELDS = ["name", "url", "username", "email", "password", "tag", "notes"];

async function openEditor(i) {
  if (!S.current) return;
  if (S.editing && !(await leaveEditor())) return;
  S.editing = { index: i };
  S.touched = false;
  const e = i >= 0 ? S.entries[i] : {};
  FIELDS.forEach((f) => (form.elements[f].value = e[f] || ""));
  form.elements.favorite.checked = !!e.favorite;
  form.elements.password.type = "password";
  $('[data-reveal="password"] use').setAttribute("href", "#i-eye");
  $("#generator").classList.add("hidden");
  $("#editor-title").textContent = i >= 0 ? "Editar item" : "Novo item";
  $("#editor-msg").textContent = "";
  paintStrength($("#strength"), form.elements.password.value);
  $("#detail-empty").classList.add("hidden");
  $("#detail").classList.add("hidden");
  form.classList.remove("hidden");
  form.scrollIntoView({ block: "start" });
  form.elements.name.focus();
}

function closeEditor() {
  S.editing = null;
  form.classList.add("hidden");
  renderDetail();
}

/** Leaves the editor, asking first if the form was changed. */
async function leaveEditor() {
  if (S.touched && !(await modal({ title: "Descartar edição?", message: "As mudanças neste item ainda não foram concluídas.", ok: "Descartar", danger: true }))) return false;
  closeEditor();
  return true;
}

form.addEventListener("input", (ev) => {
  S.touched = true;
  if (ev.target.name === "password") paintStrength($("#strength"), ev.target.value);
});
$("#editor-cancel").onclick = leaveEditor;

form.onsubmit = (ev) => {
  ev.preventDefault();
  if (!form.elements.name.value.trim()) {
    $("#editor-msg").textContent = "Dê um nome ao item.";
    return form.elements.name.focus();
  }
  const e = { favorite: form.elements.favorite.checked };
  // Notes and password keep their spaces; a password can legitimately start or end with one.
  FIELDS.forEach((f) => (e[f] = f === "notes" || f === "password" ? form.elements[f].value : form.elements[f].value.trim()));
  const { index } = S.editing;
  if (index >= 0 && !S.touched) return closeEditor(); // nothing changed: don't mark the vault dirty
  if (index >= 0) S.entries[index] = e;
  else S.entries.push(e);
  S.sel = index >= 0 ? index : S.entries.length - 1;
  S.revealed = false;
  setDirty(true);
  closeEditor();
  renderFilters();
  renderList();
  $(`.item[data-i="${S.sel}"]`)?.scrollIntoView({ block: "nearest" });
};

$("#new-entry").onclick = () => openEditor(-1);

// ---------- vault menu, CSV ----------
const menu = $("#vault-menu");
$("#vault-menu-btn").onclick = (ev) => { ev.stopPropagation(); menu.classList.toggle("hidden"); };
addEventListener("click", () => menu.classList.add("hidden"));
menu.onclick = (ev) => {
  const act = ev.target.closest("button")?.dataset.act;
  menu.classList.add("hidden");
  if (act === "import") $("#import-file").click();
  if (act === "export") exportCsv();
  if (act === "password") vaultPassword();
  if (act === "delete") deleteVault();
};

$("#import-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  try {
    const imported = await call("parse_csv", { text: await file.text() });
    const seen = new Set(S.entries.map(entryKey));
    const fresh = imported.filter((e) => !seen.has(entryKey(e)) && seen.add(entryKey(e)));
    if (!fresh.length) return toast("Nada novo para importar: todos os itens já existem no cofre.");
    const dup = imported.length - fresh.length;
    const ok = await modal({
      title: `Importar ${fresh.length} ${fresh.length === 1 ? "item" : "itens"}?`, ok: "Importar",
      message: `Para o cofre "${S.current}".${dup ? ` ${dup} duplicados serão ignorados.` : ""} Colunas desconhecidas do CSV vão para as notas de cada item.`,
    });
    if (!ok) return;
    S.entries.push(...fresh);
    setDirty(true);
    renderFilters(); renderList();
    toast(`${fresh.length} itens importados. Salve e depois apague o CSV: ele tem suas senhas em texto puro.`);
  } catch (e) { toast(e, true); }
});

async function exportCsv() {
  if (!(await modal({ title: "Exportar em texto puro?", message: "O CSV terá TODAS as senhas deste cofre sem criptografia, na pasta Downloads. Apague-o depois de usar.", ok: "Exportar", danger: true }))) return;
  try { toast(`Exportado para ${await call("export_csv", { name: S.current, entries: S.entries })}`); } catch (e) { toast(e, true); }
}

// ---------- keyboard ----------
addEventListener("keydown", async (ev) => {
  // WebView2 keeps browser reload keys; a reload would drop unsaved changes without asking.
  if (ev.key === "F5" || ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "r")) return ev.preventDefault();
  if ($("#modal").open || $("#vault-dialog").open || !document.body.classList.contains("mode-app") || S.busy) return;
  const k = ev.key.toLowerCase(), ctrl = ev.ctrlKey || ev.metaKey;

  if (S.editing) {
    if (k === "escape") { ev.preventDefault(); leaveEditor(); }
    else if (ctrl && k === "enter") { ev.preventDefault(); form.requestSubmit(); }
    else if (ctrl && k === "s") { ev.preventDefault(); save(); }
    return;
  }
  if (ctrl && k === "s") { ev.preventDefault(); save(); }
  else if (ctrl && k === "l") { ev.preventDefault(); if (await confirmDiscard()) lock(); }
  else if (ctrl && k === "f" && S.current) { ev.preventDefault(); $("#search").focus(); $("#search").select(); }
  else if (ctrl && k === "n" && S.current) { ev.preventDefault(); openEditor(-1); }
  else if (ctrl && ev.shiftKey && k === "c" && S.entries[S.sel]) { ev.preventDefault(); copy(S.entries[S.sel].password, "Senha"); }
  else if (ctrl && ev.shiftKey && k === "u" && S.entries[S.sel]) { ev.preventDefault(); const e = S.entries[S.sel]; copy(e.username || e.email, "Usuário"); }
  else if ((k === "arrowdown" || k === "arrowup") && S.visible.length && (!typing() || document.activeElement === $("#search"))) {
    ev.preventDefault();
    const pos = S.visible.indexOf(S.sel);
    const next = pos < 0 ? 0 : Math.min(Math.max(pos + (k === "arrowdown" ? 1 : -1), 0), S.visible.length - 1);
    select(S.visible[next], true);
  }
  else if (k === "enter" && S.entries[S.sel] && !typing()) { ev.preventDefault(); openEditor(S.sel); }
  else if (k === "delete" && S.entries[S.sel] && !typing()) { ev.preventDefault(); deleteEntry(); }
  else if (k === "escape" && document.activeElement === $("#search")) { $("#search").value = ""; renderList(); $("#search").blur(); }
});

// A page (re)load always starts locked, in the small login layout.
(async () => {
  await invoke("lock");
  if (await win.isResizable()) await layout(false);
  await initLogin();
})();
