//! Minimal GitHub "contents" API client: list, get, put, delete files in a repo.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::time::Duration;

/// Error text for a stale sha (file changed elsewhere); the UI matches on it to offer a merge.
pub const CONFLICT: &str = "O cofre foi alterado em outro dispositivo.";

#[derive(Clone)]
pub struct Repo {
    pub token: String,
    pub name: String, // "owner/repo"
}

#[derive(Deserialize)]
struct Item {
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct File {
    content: String,
    sha: String,
}

#[derive(Deserialize)]
struct RepoInfo {
    private: bool,
}

/// Percent-encodes a path segment (vault names may contain spaces or accents).
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(401, _) => "Token do GitHub inválido ou expirado.".into(),
        ureq::Error::Status(403, r) => format!("GitHub recusou o acesso (permissão do token ou limite de requisições): {}", r.into_string().unwrap_or_default()),
        ureq::Error::Status(404, _) => "Não encontrado (confira o repositório e se o token tem acesso a ele).".into(),
        ureq::Error::Status(409 | 422, _) => CONFLICT.into(),
        ureq::Error::Status(code, r) => format!("GitHub respondeu {code}: {}", r.into_string().unwrap_or_default()),
        ureq::Error::Transport(t) => format!("Falha de rede: {t}"),
    }
}

impl Repo {
    fn req(&self, method: &str, path: &str) -> ureq::Request {
        // URPM_GITHUB_API lets tests point at a local mock server.
        let api = std::env::var("URPM_GITHUB_API").unwrap_or_else(|_| "https://api.github.com".into());
        // Timeouts: a stalled request must not hang the app (ureq has no read timeout by default).
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(15)).timeout(Duration::from_secs(60)).build();
        agent
            .request(method, &format!("{api}/repos/{}{path}", self.name))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", concat!("urpm/", env!("CARGO_PKG_VERSION")))
    }

    /// Checks access; returns whether the repo is private.
    pub fn check(&self) -> Result<bool, String> {
        let info: RepoInfo = self.req("GET", "").call().map_err(err)?.into_json().map_err(|e| e.to_string())?;
        Ok(info.private)
    }

    /// File names in the repo root ending with `ext`.
    pub fn list(&self, ext: &str) -> Result<Vec<String>, String> {
        let items: Vec<Item> = match self.req("GET", "/contents/").call() {
            Ok(r) => r.into_json().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(404, _)) => return Ok(vec![]), // empty repo has no contents yet
            Err(e) => return Err(err(e)),
        };
        let mut names: Vec<String> = items.into_iter().filter(|i| i.kind == "file" && i.name.ends_with(ext)).map(|i| i.name).collect();
        names.sort_by_key(|n| n.to_lowercase());
        Ok(names)
    }

    /// Returns (bytes, sha).
    pub fn get(&self, path: &str) -> Result<(Vec<u8>, String), String> {
        let url = format!("/contents/{}", enc(path));
        let f: File = self.req("GET", &url).call().map_err(err)?.into_json().map_err(|e| e.to_string())?;
        // Files over 1 MB come back without inline content; fetch the raw bytes instead.
        if f.content.is_empty() {
            let mut bytes = Vec::new();
            let resp = self.req("GET", &url).set("Accept", "application/vnd.github.raw").call().map_err(err)?;
            resp.into_reader().take(100 << 20).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            return Ok((bytes, f.sha));
        }
        let clean: String = f.content.chars().filter(|c| !c.is_whitespace()).collect();
        Ok((B64.decode(clean).map_err(|e| e.to_string())?, f.sha))
    }

    /// Current sha of a file, or None if it doesn't exist (cheap way to detect changes made elsewhere).
    pub fn sha(&self, path: &str) -> Result<Option<String>, String> {
        #[derive(Deserialize)]
        struct Meta {
            sha: String,
        }
        match self.req("GET", &format!("/contents/{}", enc(path))).call() {
            Ok(r) => Ok(Some(r.into_json::<Meta>().map_err(|e| e.to_string())?.sha)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(err(e)),
        }
    }

    /// Creates (sha = None) or updates a file; returns the new sha. A stale sha fails instead of overwriting.
    pub fn put(&self, path: &str, bytes: &[u8], sha: Option<&str>, message: &str) -> Result<String, String> {
        let mut body = json!({ "message": message, "content": B64.encode(bytes) });
        if let Some(s) = sha {
            body["sha"] = s.into();
        }
        let r: serde_json::Value = self.req("PUT", &format!("/contents/{}", enc(path))).send_json(body).map_err(err)?.into_json().map_err(|e| e.to_string())?;
        r["content"]["sha"].as_str().map(String::from).ok_or_else(|| "Resposta inesperada do GitHub.".into())
    }

    pub fn delete(&self, path: &str, sha: &str, message: &str) -> Result<(), String> {
        self.req("DELETE", &format!("/contents/{}", enc(path))).send_json(json!({ "message": message, "sha": sha })).map_err(err)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    /// Tests that point URPM_GITHUB_API (process-wide) at a fake server hold this for their whole run.
    pub(crate) static API_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn encodes_path() {
        assert_eq!(super::enc("Lojão da 7.vault"), "Loj%C3%A3o%20da%207.vault");
    }

    fn decode(s: &str) -> String {
        let b = s.as_bytes();
        let (mut out, mut i) = (Vec::new(), 0);
        while i < b.len() {
            if b[i] == b'%' {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// One request per connection: returns (status, json body).
    fn handle(files: &mut std::collections::HashMap<String, (Vec<u8>, String)>, next: &mut u32, method: &str, path: &str, raw: bool, body: &[u8]) -> (u16, serde_json::Value) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use serde_json::json;
        let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let Some(rest) = path.strip_prefix("/repos/o/r") else { return (404, json!({})) };
        if rest.is_empty() {
            return (200, json!({ "private": true }));
        }
        let name = decode(rest.strip_prefix("/contents/").unwrap_or(""));
        match (method, name.as_str()) {
            ("GET", "") if files.is_empty() => (404, json!({ "message": "This repository is empty." })),
            ("GET", "") => (200, json!(files.keys().map(|k| json!({ "name": k, "type": "file" })).collect::<Vec<_>>())),
            ("GET", n) => match files.get(n) {
                // Like GitHub for files > 1 MB: no inline content, raw bytes on request (sent as a JSON string here).
                Some((b, _)) if n.starts_with("big") && raw => (200, json!(String::from_utf8(b.clone()).unwrap())),
                Some((_, sha)) if n.starts_with("big") => (200, json!({ "content": "", "encoding": "none", "sha": sha })),
                // Real GitHub wraps base64 at 60 chars with '\n'.
                Some((b, sha)) => {
                    let wrapped = B64.encode(b).as_bytes().chunks(60).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
                    (200, json!({ "content": wrapped + "\n", "sha": sha }))
                }
                None => (404, json!({})),
            },
            ("PUT", n) => {
                let ok = match (files.get(n), req["sha"].as_str()) {
                    (None, None) => true,
                    (Some((_, cur)), Some(s)) => cur == s,
                    _ => false,
                };
                if !ok {
                    return (409, json!({ "message": "sha mismatch" }));
                }
                *next += 1;
                let sha = format!("sha{next}");
                files.insert(n.into(), (B64.decode(req["content"].as_str().unwrap()).unwrap(), sha.clone()));
                (200, json!({ "content": { "sha": sha } }))
            }
            ("DELETE", n) => match files.get(n) {
                Some((_, cur)) if req["sha"].as_str() == Some(cur.as_str()) => {
                    files.remove(n);
                    (200, json!({}))
                }
                _ => (409, json!({ "message": "sha mismatch" })),
            },
            _ => (405, json!({})),
        }
    }

    pub(crate) fn fake_github() -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut files, mut next) = (Default::default(), 0);
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut rd = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                rd.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                let (mut len, mut raw) = (0, false);
                loop {
                    let mut h = String::new();
                    rd.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap();
                        }
                        raw |= k.eq_ignore_ascii_case("accept") && v.contains("github.raw");
                    }
                }
                let mut body = vec![0; len];
                rd.read_exact(&mut body).unwrap();
                let (status, json) = handle(&mut files, &mut next, &method, &path, raw, &body);
                let out = json.to_string();
                let _ = write!(stream, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn roundtrip_against_fake_github() {
        let _api = API_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("URPM_GITHUB_API", fake_github());
        let repo = super::Repo { token: "t".into(), name: "o/r".into() };
        assert!(repo.check().unwrap());
        assert!(repo.list(".vault").unwrap().is_empty(), "404 on empty repo lists nothing");

        let data: Vec<u8> = (0..=255u8).cycle().take(500).collect(); // long enough for multi-line base64
        let sha1 = repo.put("a.vault", &data, None, "create").unwrap();
        assert_eq!(repo.get("a.vault").unwrap(), (data.clone(), sha1.clone()));
        let sha2 = repo.put("a.vault", b"v2", Some(&sha1), "update").unwrap();
        let stale = repo.put("a.vault", b"v3", Some(&sha1), "stale").unwrap_err();
        assert_eq!(stale, super::CONFLICT);
        assert!(repo.put("a.vault", b"v3", None, "blind create").is_err());

        repo.put("notes.txt", b"x", None, "other ext").unwrap();
        let odd = "Lojão da 7.vault";
        let sha_odd = repo.put(odd, b"acentos", None, "create").unwrap();
        assert_eq!(repo.get(odd).unwrap().0, b"acentos");
        assert_eq!(repo.list(".vault").unwrap(), vec!["a.vault", odd]);

        // >1 MB path: raw fallback, keeping the sha from the metadata response.
        let sha_big = repo.put("big.vault", b"grande", None, "create").unwrap();
        assert_eq!(repo.get("big.vault").unwrap(), (b"\"grande\"".to_vec(), sha_big.clone()));
        repo.delete("big.vault", &sha_big, "delete").unwrap();

        assert!(repo.delete(odd, &sha1, "stale delete").is_err());
        assert_eq!(repo.sha(odd).unwrap(), Some(sha_odd.clone()));
        repo.delete(odd, &sha_odd, "delete").unwrap();
        assert_eq!(repo.sha(odd).unwrap(), None, "deleted file has no sha");
        assert_eq!(repo.list(".vault").unwrap(), vec!["a.vault"]);
        assert_eq!(repo.get("a.vault").unwrap(), (b"v2".to_vec(), sha2));
    }
}
