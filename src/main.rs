#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod github;
mod vault;

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, State};

use crypto::VaultKey;
use github::Repo;
use vault::{Entry, Vault};

const EXT: &str = ".vault";
const KEYRING: &str = "urpm-tauri";
/// Marks a repo as set up for URPM and lets the master password be checked even with no vaults.
const ACCOUNT_FILE: &str = "urpm3-account.json";
const ACCOUNT_CHECK: &[u8] = b"urpm3-account-v1";
const MIN_MASTER: usize = 10;
const MIN_VAULT_PASSWORD: usize = 8;

struct Session {
    repo: Repo,
    master: String,
    /// Repo has no URPM data yet: only `setup_repo` may run until it creates the master password.
    setup: bool,
    /// Open vaults: cached key + last known GitHub sha (None = never uploaded).
    open: HashMap<String, (VaultKey, Option<String>)>,
}

#[derive(Default)]
struct AppState(Mutex<Option<Session>>);

/// Last secret this app put on the clipboard, so lock/exit can wipe it.
#[derive(Default)]
struct LastCopy(Mutex<Option<String>>);


/// Clears the clipboard only if it still holds `text` (never wipes something the user copied later).
fn clear_clipboard_if(text: &str) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.get_text().ok().as_deref() == Some(text) {
            let _ = cb.clear();
        }
    }
}

fn clear_last_copy(app: &tauri::AppHandle) {
    if let Some(t) = app.state::<LastCopy>().0.lock().ok().and_then(|mut g| g.take()) {
        clear_clipboard_if(&t);
    }
}

type R<T> = Result<T, String>;

fn with<T>(state: &State<AppState>, f: impl FnOnce(&mut Session) -> R<T>) -> R<T> {
    let mut guard = state.0.lock().map_err(|_| "Estado interno corrompido.")?;
    let s = guard.as_mut().ok_or("Sessão bloqueada. Entre novamente.")?;
    if s.setup {
        return Err("Crie a senha mestra deste repositório primeiro.".into());
    }
    f(s)
}

fn keyring(user: &str) -> R<keyring::Entry> {
    keyring::Entry::new(KEYRING, user).map_err(|e| e.to_string())
}

fn file_of(name: &str) -> String {
    format!("{name}{EXT}")
}

fn vault_names(files: Vec<String>) -> Vec<String> {
    files.iter().filter_map(|f| f.strip_suffix(EXT)).filter(|n| valid_name(n).is_ok()).map(String::from).collect()
}

fn valid_name(name: &str) -> R<()> {
    let ok = !name.is_empty()
        && name.chars().count() <= 48
        && name.trim() == name
        && name.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
    if ok { Ok(()) } else { Err("Use até 48 letras, números, espaço, '-' ou '_' no nome do cofre.".into()) }
}

fn check_vault_password(p: Option<String>) -> R<Option<String>> {
    match p {
        Some(p) if p.chars().count() < MIN_VAULT_PASSWORD => Err(format!("Use pelo menos {MIN_VAULT_PASSWORD} caracteres na senha do cofre.")),
        p => Ok(p),
    }
}

/// Opens a vault from GitHub and caches its key; returns its entries.
fn load(s: &mut Session, name: &str, extra: Option<&str>) -> R<Vec<Entry>> {
    let (bytes, sha) = s.repo.get(&file_of(name))?;
    let cached = s.open.get(name).map(|(k, _)| k);
    let (key, pt) = crypto::open(&bytes, cached, &s.master, extra)?;
    let v: Vault = serde_json::from_slice(&pt).map_err(|_| "Conteúdo do cofre ilegível.")?;
    s.open.insert(name.to_string(), (key, Some(sha)));
    Ok(v.entries)
}

/// Uploads a new empty vault (fails instead of overwriting an existing file).
fn create(s: &mut Session, name: &str, extra: Option<&str>) -> R<()> {
    valid_name(name)?;
    if s.repo.list(EXT)?.iter().any(|f| f.eq_ignore_ascii_case(&file_of(name))) {
        return Err(format!("Já existe um cofre chamado \"{name}\"."));
    }
    let key = VaultKey::new(&s.master, extra)?;
    let pt = serde_json::to_vec(&Vault::default()).map_err(|e| e.to_string())?;
    let sha = s.repo.put(&file_of(name), &key.seal(&pt), None, &format!("URPM: criar cofre {name}"))?;
    s.open.insert(name.to_string(), (key, Some(sha)));
    Ok(())
}

#[derive(Serialize)]
struct Saved {
    repo: String,
    has_token: bool,
}

#[tauri::command]
fn saved_login() -> Saved {
    let get = |u| keyring(u).ok().and_then(|e| e.get_password().ok());
    Saved { repo: get("repo").unwrap_or_default(), has_token: get("github-token").is_some() }
}

#[tauri::command]
fn forget_token() -> R<()> {
    match keyring("github-token")?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Serialize)]
struct Connected {
    vaults: Vec<String>,
    private: bool,
    /// Repo has no URPM data: the UI must ask for a new master password (`setup_repo`).
    setup: bool,
    /// Files already in the repo that aren't URPM's (shown on the setup screen; never touched).
    other_files: usize,
}

#[tauri::command(async)]
fn connect(state: State<AppState>, token: String, repo: String, master: String, remember: bool) -> R<Connected> {
    let typed_token = !token.trim().is_empty();
    let token = match token.trim() {
        "" => keyring("github-token")?.get_password().map_err(|_| "Informe o token do GitHub.")?,
        t => t.to_string(),
    };
    let repo = repo.trim().trim_start_matches("https://github.com/").trim_end_matches(".git").trim_matches('/').to_string();
    if repo.split('/').count() != 2 {
        return Err("Informe o repositório como usuario/repositorio.".into());
    }
    if master.is_empty() {
        return Err("Digite a senha mestra.".into());
    }
    let (s, connected) = start_session(Repo { token, name: repo }, master)?;
    keyring("repo")?.set_password(&s.repo.name).map_err(|e| e.to_string())?;
    if remember {
        keyring("github-token")?.set_password(&s.repo.token).map_err(|e| format!("Não foi possível guardar o token: {e}"))?;
    } else if typed_token {
        // A new token the user chose not to remember must not leave the old one paired with the new repo.
        forget_token()?;
    }
    *state.0.lock().map_err(|_| "Estado interno corrompido.")? = Some(s);
    Ok(connected)
}

/// Checks the repo and the master password (or detects a new repo, which then needs `setup_repo`).
fn start_session(repo: Repo, master: String) -> R<(Session, Connected)> {
    let mut s = Session { repo, master, setup: false, open: HashMap::new() };
    let private = s.repo.check()?;
    let files = s.repo.list("")?;
    let vaults = vault_names(files.iter().filter(|f| f.ends_with(EXT)).cloned().collect());
    let mut other_files = 0;
    if files.iter().any(|f| f == ACCOUNT_FILE) {
        let (bytes, _) = s.repo.get(ACCOUNT_FILE)?;
        match crypto::open(&bytes, None, &s.master, None) {
            Ok((_, pt)) if pt == ACCOUNT_CHECK => {}
            Ok(_) => return Err("Arquivo de conta do URPM inválido.".into()),
            Err(e) => return Err(e),
        }
    } else if vaults.is_empty() {
        // New repo (empty, or only non-URPM files): nothing to verify, the UI runs the setup.
        s.setup = true;
        s.master.clear();
        other_files = files.len();
    } else {
        // Vaults from before the account file existed: prove the master password by opening one
        // (a vault that is protected or unreadable for another reason doesn't block the others),
        // but never log in with a password nothing could verify.
        let mut last_err = None;
        for name in &vaults {
            match load(&mut s, name, None) {
                Ok(_) => { last_err = None; break; }
                Err(e) if e == crypto::WRONG_PASSWORD => return Err(e),
                Err(e) => last_err = Some(e),
            }
        }
        if let Some(e) = last_err {
            return Err(if e == crypto::NEEDS_VAULT_PASSWORD {
                "Não foi possível confirmar a senha mestra: nenhum cofre deste repositório abre só com ela.".into()
            } else {
                format!("Não foi possível confirmar a senha mestra: {e}")
            });
        }
        // From now on the account file verifies the password (another device may have just created it).
        match s.repo.put(ACCOUNT_FILE, &VaultKey::new(&s.master, None)?.seal(ACCOUNT_CHECK), None, "URPM: criar arquivo de conta") {
            Ok(_) => {}
            Err(e) if e == github::CONFLICT => {}
            Err(e) => return Err(e),
        }
    }
    let setup = s.setup;
    Ok((s, Connected { vaults, private, setup, other_files }))
}

#[derive(Serialize)]
struct SetupDone {
    vaults: Vec<String>,
    /// Set when the master password was created but the first vault couldn't be (the repo is configured anyway).
    warning: Option<String>,
}

/// First run on a new repo: sets its master password (account file) and creates the first vault.
#[tauri::command(async)]
fn setup_repo(state: State<AppState>, master: String, vault: String, vault_password: Option<String>) -> R<SetupDone> {
    if master.chars().count() < MIN_MASTER {
        return Err(format!("Use pelo menos {MIN_MASTER} caracteres na senha mestra."));
    }
    valid_name(&vault)?;
    let extra = check_vault_password(vault_password)?;
    let mut guard = state.0.lock().map_err(|_| "Estado interno corrompido.")?;
    let s = guard.as_mut().ok_or("Sessão bloqueada. Entre novamente.")?;
    do_setup(s, master, &vault, extra.as_deref())
}

fn do_setup(s: &mut Session, master: String, vault: &str, extra: Option<&str>) -> R<SetupDone> {
    if !s.setup {
        return Err("Este repositório já está configurado.".into());
    }
    // put(sha = None) fails if the file appeared meanwhile, so two devices can't both set a password.
    s.repo
        .put(ACCOUNT_FILE, &VaultKey::new(&master, None)?.seal(ACCOUNT_CHECK), None, "URPM: configurar repositório")
        .map_err(|e| if e == github::CONFLICT { "Este repositório acabou de ser configurado em outro dispositivo. Entre de novo.".to_string() } else { e })?;
    s.master = master;
    s.setup = false;
    // The repo is configured from here on; a failed first vault must not leave the UI stuck on the setup screen.
    let warning = create(s, vault, extra).err().map(|e| format!("A senha mestra foi criada, mas o cofre \"{vault}\" não: {e}"));
    let vaults = vault_names(s.repo.list(EXT).unwrap_or_default());
    Ok(SetupDone { vaults, warning })
}

// async: these wait on the session mutex, which a slow GitHub call may hold; keep the UI thread free.
#[tauri::command(async)]
fn lock(app: tauri::AppHandle, state: State<AppState>) {
    clear_last_copy(&app);
    if let Ok(mut g) = state.0.lock() {
        *g = None;
    }
}

/// Copies a secret, kept out of Windows clipboard history/cloud sync, and wipes it after `seconds` (5–600).
#[tauri::command]
fn copy_secret(app: tauri::AppHandle, text: String, seconds: u64) -> R<()> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("Área de transferência indisponível: {e}"))?;
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        cb.set().exclude_from_history().exclude_from_cloud().text(text.clone())
    };
    #[cfg(not(windows))]
    let set = cb.set_text(text.clone());
    set.map_err(|e| format!("Não foi possível copiar: {e}"))?;
    *app.state::<LastCopy>().0.lock().map_err(|_| "Estado interno corrompido.")? = Some(text.clone());
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(seconds.clamp(5, 600)));
        clear_clipboard_if(&text);
    });
    Ok(())
}

#[tauri::command(async)]
fn list_vaults(state: State<AppState>) -> R<Vec<String>> {
    with(&state, |s| Ok(vault_names(s.repo.list(EXT)?)))
}

/// `password` is the vault's own password, only needed for protected vaults that aren't open yet.
#[tauri::command(async)]
fn open_vault(state: State<AppState>, name: String, password: Option<String>) -> R<Vec<Entry>> {
    with(&state, |s| load(s, &name, password.as_deref()))
}

/// Compares the open vault with GitHub: "same", "changed" (saved on another device) or "deleted".
#[tauri::command(async)]
fn remote_status(state: State<AppState>, name: String) -> R<&'static str> {
    // Copy what's needed and release the session lock before the network call: a slow background
    // check must never delay a save, an open or the lock.
    let (repo, known) = with(&state, |s| {
        let known = s.open.get(&name).and_then(|(_, sha)| sha.clone()).ok_or("Cofre não está aberto.")?;
        Ok((s.repo.clone(), known))
    })?;
    Ok(match repo.sha(&file_of(&name))? {
        None => "deleted",
        Some(sha) if sha == known => "same",
        Some(_) => "changed",
    })
}

/// Sets, changes (Some) or removes (None) a vault's own password by re-encrypting its saved entries with a new key.
#[tauri::command(async)]
fn set_vault_password(state: State<AppState>, name: String, password: Option<String>, entries: Vec<Entry>) -> R<()> {
    let extra = check_vault_password(password)?;
    with(&state, |s| rekey(s, name, extra.as_deref(), entries))
}

fn rekey(s: &mut Session, name: String, extra: Option<&str>, entries: Vec<Entry>) -> R<()> {
    let sha = s.open.get(&name).and_then(|(_, sha)| sha.clone()).ok_or("Abra o cofre antes de alterar a senha.")?;
    let key = VaultKey::new(&s.master, extra)?;
    let pt = serde_json::to_vec(&Vault { entries }).map_err(|e| e.to_string())?;
    let msg = format!("URPM: {} senha do cofre {name}", if extra.is_some() { "definir" } else { "remover" });
    let new_sha = s.repo.put(&file_of(&name), &key.seal(&pt), Some(&sha), &msg)?;
    s.open.insert(name, (key, Some(new_sha)));
    Ok(())
}

#[tauri::command(async)]
fn save_vault(state: State<AppState>, name: String, entries: Vec<Entry>) -> R<()> {
    with(&state, |s| {
        let (key, sha) = s.open.get_mut(&name).ok_or("Abra o cofre antes de salvar.")?;
        let pt = serde_json::to_vec(&Vault { entries }).map_err(|e| e.to_string())?;
        let new_sha = s.repo.put(&file_of(&name), &key.seal(&pt), sha.as_deref(), &format!("URPM: atualizar cofre {name}"))?;
        *sha = Some(new_sha);
        Ok(())
    })
}

#[tauri::command(async)]
fn create_vault(state: State<AppState>, name: String, password: Option<String>) -> R<()> {
    let extra = check_vault_password(password)?;
    with(&state, |s| create(s, &name, extra.as_deref()))
}

#[tauri::command(async)]
fn delete_vault(state: State<AppState>, name: String) -> R<()> {
    valid_name(&name)?;
    with(&state, |s| {
        let sha = match s.open.get(&name).and_then(|(_, sha)| sha.clone()) {
            Some(sha) => sha,
            None => s.repo.get(&file_of(&name))?.1,
        };
        s.repo.delete(&file_of(&name), &sha, &format!("URPM: apagar cofre {name}"))?;
        s.open.remove(&name);
        Ok(())
    })
}

/// Small fixed login window vs. large resizable manager window (same window, resized and re-centered).
/// Returns false when the window is minimized: Windows ignores style/size changes then, so the UI retries on restore.
#[tauri::command]
fn set_layout(window: tauri::WebviewWindow, main: bool) -> R<bool> {
    use tauri::LogicalSize;
    let e = |e: tauri::Error| e.to_string();
    if window.is_minimized().map_err(e)? {
        return Ok(false);
    }
    let (mut w, mut h, mut min): (f64, f64, (f64, f64)) = if main { (1200.0, 780.0, (920.0, 600.0)) } else { (400.0, 620.0, (400.0, 620.0)) };
    // Never larger than the monitor's work area (small laptop screens / high scaling), or the titlebar ends up off-screen.
    if let Some(m) = window.current_monitor().map_err(e)? {
        let area = m.work_area().size.to_logical::<f64>(m.scale_factor());
        (w, h) = (w.min(area.width - 24.0), h.min(area.height - 24.0));
        min = (min.0.min(w), min.1.min(h));
    }
    // Only take the foreground if we already had it: the idle lock fires while the user works in other apps.
    let focused = window.is_focused().map_err(e)?;
    if focused {
        window.hide().map_err(e)?;
    }
    if !main {
        window.unmaximize().map_err(e)?;
    }
    window.set_min_size(None::<LogicalSize<f64>>).map_err(e)?;
    window.set_resizable(main).map_err(e)?;
    window.set_maximizable(main).map_err(e)?;
    window.set_size(LogicalSize::new(w, h)).map_err(e)?;
    window.set_min_size(Some(LogicalSize::new(min.0, min.1))).map_err(e)?;
    window.center().map_err(e)?;
    if focused {
        window.show().map_err(e)?;
        window.set_focus().map_err(e)?;
    }
    Ok(true)
}

/// Opens an http(s) link in the default browser.
#[tauri::command]
fn open_url(url: String) -> R<()> {
    let url = url.trim();
    // explorer.exe splits its arguments on commas (/select,<path>), so never hand it a raw comma.
    let url = if url.contains("://") { url.to_string() } else { format!("https://{url}") }.replace(',', "%2C");
    // Only web links, and no quotes/spaces: explorer.exe would otherwise accept local paths too.
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.chars().any(|c| c.is_whitespace() || c == '"') {
        return Err("Endereço inválido.".into());
    }
    std::process::Command::new("explorer.exe").arg(&url).spawn().map_err(|e| format!("Não foi possível abrir o navegador: {e}"))?;
    Ok(())
}

#[tauri::command]
fn parse_csv(text: String) -> R<Vec<Entry>> {
    vault::parse_csv(&text)
}

/// Writes a plaintext CSV to the Downloads folder and returns its path.
#[tauri::command]
fn export_csv(app: tauri::AppHandle, name: String, entries: Vec<Entry>) -> R<String> {
    valid_name(&name)?;
    let dir = app.path().download_dir().map_err(|e| e.to_string())?;
    let path = dir.join(format!("{name}_exportado.csv"));
    std::fs::write(&path, vault::to_csv(&entries)?).map_err(|e| format!("Não foi possível gravar o arquivo: {e}"))?;
    Ok(path.display().to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .manage(LastCopy::default())
        .invoke_handler(tauri::generate_handler![
            saved_login, forget_token, connect, setup_repo, lock, copy_secret, list_vaults, open_vault, set_vault_password, save_vault,
            create_vault, delete_vault, remote_status, parse_csv, export_csv, set_layout, open_url
        ])
        .build(tauri::generate_context!())
        .expect("erro ao iniciar o URPM")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                clear_last_copy(app);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    fn repo() -> Repo {
        Repo { token: "t".into(), name: "o/r".into() }
    }

    /// Fresh in-memory GitHub for one scenario; the guard keeps other tests off URPM_GITHUB_API meanwhile.
    fn fresh_github() -> MutexGuard<'static, ()> {
        let g = github::tests::API_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("URPM_GITHUB_API", github::tests::fake_github());
        g
    }

    fn session(master: &str) -> Session {
        Session { repo: repo(), master: master.into(), setup: false, open: HashMap::new() }
    }

    fn has_account() -> bool {
        repo().list("").unwrap().iter().any(|f| f == ACCOUNT_FILE)
    }

    #[test]
    fn empty_repo_setup_then_login() {
        let _g = fresh_github();
        let (mut s, c) = start_session(repo(), "mestra-certa".into()).unwrap();
        assert!(c.setup && c.vaults.is_empty() && c.other_files == 0);
        assert!(s.setup && s.master.is_empty());
        let (mut other, _) = start_session(repo(), "qualquer".into()).unwrap(); // second device, also in setup

        let done = do_setup(&mut s, "mestra-certa".into(), "Pessoal", None).unwrap();
        assert_eq!((done.vaults, done.warning), (vec!["Pessoal".to_string()], None));
        assert!(!s.setup && s.master == "mestra-certa" && s.open.contains_key("Pessoal"));
        assert_eq!(do_setup(&mut s, "mestra-certa".into(), "Outro", None).err().unwrap(), "Este repositório já está configurado.");
        assert!(do_setup(&mut other, "outra-mestra".into(), "Outro", None).err().unwrap().contains("outro dispositivo"));
        assert!(has_account());
        assert_eq!(vault_names(repo().list(EXT).unwrap()), vec!["Pessoal"]);

        let (mut s, c) = start_session(repo(), "mestra-certa".into()).unwrap();
        assert!(!c.setup && c.vaults == vec!["Pessoal"]);
        assert!(load(&mut s, "Pessoal", None).unwrap().is_empty());
        assert_eq!(start_session(repo(), "mestra-errada".into()).err().unwrap(), crypto::WRONG_PASSWORD);
    }

    #[test]
    fn repo_with_other_files_needs_setup() {
        let _g = fresh_github();
        repo().put("README.md", b"# oi", None, "readme").unwrap();
        let (_, c) = start_session(repo(), "mestra".into()).unwrap();
        assert!(c.setup && c.vaults.is_empty() && c.other_files == 1);
    }

    #[test]
    fn legacy_repo_gets_account_file() {
        let _g = fresh_github();
        create(&mut session("mestra-legada"), "Antigo", None).unwrap(); // vault from before the account file
        assert!(!has_account());

        assert_eq!(start_session(repo(), "mestra-errada".into()).err().unwrap(), crypto::WRONG_PASSWORD);
        assert!(!has_account(), "a wrong password must not create the account file");

        let (_, c) = start_session(repo(), "mestra-legada".into()).unwrap();
        assert!(!c.setup && c.vaults == vec!["Antigo"]);
        assert!(has_account());
        assert!(!start_session(repo(), "mestra-legada".into()).unwrap().1.setup, "account file verifies the password now");
    }

    #[test]
    fn legacy_repo_never_logs_in_unverified() {
        let _g = fresh_github();
        create(&mut session("mestra"), "Trancado", Some("senha-do-cofre")).unwrap(); // only a protected vault, no account file
        let err = start_session(repo(), "qualquer-coisa".into()).err().unwrap();
        assert!(err.contains("Não foi possível confirmar"), "{err}");
        assert!(!has_account());
    }

    #[test]
    fn protected_vault_flow() {
        let _g = fresh_github();
        let entries = vec![Entry { name: "GitHub".into(), password: "p4ss".into(), ..Default::default() }];
        let mut s = session("mestra");
        create(&mut s, "Secreto", None).unwrap();
        rekey(&mut s, "Secreto".into(), Some("senha-do-cofre"), entries.clone()).unwrap();
        create(&mut s, "Novo", Some("senha-do-cofre")).unwrap();

        let mut s = session("mestra");
        assert_eq!(load(&mut s, "Novo", None).err().unwrap(), crypto::NEEDS_VAULT_PASSWORD);
        assert_eq!(load(&mut s, "Secreto", None).err().unwrap(), crypto::NEEDS_VAULT_PASSWORD);
        assert_eq!(load(&mut s, "Secreto", Some("errada-123")).err().unwrap(), crypto::WRONG_VAULT_PASSWORD);
        assert_eq!(load(&mut s, "Secreto", Some("senha-do-cofre")).unwrap(), entries);
        assert_eq!(load(&mut s, "Secreto", None).unwrap(), entries, "an open vault reloads with its cached key");

        rekey(&mut s, "Secreto".into(), None, entries.clone()).unwrap();
        assert_eq!(load(&mut session("mestra"), "Secreto", None).unwrap(), entries);
    }
}
