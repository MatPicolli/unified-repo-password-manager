//! Vault contents and CSV import/export.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(default)]
pub struct Entry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub notes: String,
    pub tag: String,
    pub favorite: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

#[derive(Clone, Copy, PartialEq)]
enum Field {
    Name,
    Url,
    Username,
    Email,
    Password,
    Notes,
    Tag,
    Favorite,
}

fn normalize(h: &str) -> String {
    h.trim()
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' => 'a',
            'é' | 'ê' => 'e',
            'í' => 'i',
            'ó' | 'ô' | 'õ' => 'o',
            'ú' | 'ü' => 'u',
            'ç' => 'c',
            '-' | '_' | '.' => ' ',
            c => c,
        })
        .collect()
}

fn field_of(header: &str) -> Option<Field> {
    use Field::*;
    Some(match normalize(header).as_str() {
        "name" | "nome" | "title" | "titulo" | "servico" | "service" | "account" | "conta" => Name,
        "url" | "site" | "website" | "web site" | "login uri" | "uri" | "endereco" | "link" => Url,
        "username" | "usuario" | "user" | "login" | "login username" | "user name" | "login name" => Username,
        "email" | "e mail" | "mail" => Email,
        "password" | "senha" | "pass" | "login password" | "palavra passe" => Password,
        "notes" | "notas" | "note" | "extra" | "comments" | "comentarios" | "observacoes" | "obs" => Notes,
        "tag" | "tags" | "folder" | "grouping" | "pasta" | "grupo" | "group" | "categoria" => Tag,
        "favorite" | "favorito" | "fav" => Favorite,
        _ => return None,
    })
}

/// Parses a CSV with a header row (URPM/Bitwarden/Chrome-like or the old Python app's columns).
pub fn parse_csv(text: &str) -> Result<Vec<Entry>, String> {
    let text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(|e| format!("CSV inválido: {e}"))?.clone();
    let cols: Vec<Option<Field>> = headers.iter().map(field_of).collect();
    if !cols.contains(&Some(Field::Password)) || !cols.contains(&Some(Field::Name)) {
        return Err(format!(
            "Cabeçalho não reconhecido ({}). O CSV precisa ter ao menos colunas de nome e senha.",
            headers.iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let mut out = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| format!("CSV inválido: {e}"))?;
        let mut e = Entry::default();
        let mut extra = Vec::new();
        for (i, raw) in rec.iter().enumerate() {
            let v = raw.trim().to_string();
            match cols.get(i).copied().flatten() {
                Some(Field::Name) => e.name = v,
                Some(Field::Url) => e.url = v,
                Some(Field::Username) => e.username = v,
                Some(Field::Email) => e.email = v,
                Some(Field::Password) => e.password = raw.to_string(), // spaces can be part of a password
                Some(Field::Notes) => e.notes = raw.to_string(),
                // "Nenhum" was the old Python app's "no tag" value.
                Some(Field::Tag) => e.tag = if v == "Nenhum" { String::new() } else { v },
                Some(Field::Favorite) => e.favorite = matches!(v.to_lowercase().as_str(), "1" | "true" | "sim" | "yes" | "x"),
                // Unknown columns (TOTP seeds, custom fields...) are kept in the notes instead of being dropped.
                None if !v.is_empty() => extra.push(format!("{}: {raw}", headers.get(i).unwrap_or("?").trim())),
                None => {}
            }
        }
        if !extra.is_empty() {
            let sep = if e.notes.is_empty() { "" } else { "\n" };
            e.notes = format!("{}{sep}{}", e.notes, extra.join("\n"));
        }
        if e != Entry::default() {
            out.push(e);
        }
    }
    Ok(out)
}

pub fn to_csv(entries: &[Entry]) -> Result<String, String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(["name", "url", "username", "email", "password", "notes", "tag", "favorite"]).map_err(|e| e.to_string())?;
    for e in entries {
        let fav = if e.favorite { "true" } else { "false" };
        w.write_record([&e.name, &e.url, &e.username, &e.email, &e.password, &e.notes, &e.tag, fav]).map_err(|e| e.to_string())?;
    }
    String::from_utf8(w.into_inner().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_old_python_format() {
        let csv = "Serviço,Usuário,Senha,E-mail,Notas,Tag\nNetflix,eu,s3nh@,\"a@b.c\",\"linha1\nlinha2\",Nenhum\nBanco,x,y,,,Vermelho\n";
        let v = parse_csv(csv).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "Netflix");
        assert_eq!(v[0].password, "s3nh@");
        assert_eq!(v[0].notes, "linha1\nlinha2");
        assert_eq!(v[0].tag, "");
        assert_eq!(v[1].tag, "Vermelho");
    }

    #[test]
    fn export_then_import_roundtrip() {
        let e = Entry { name: "a,b".into(), password: "p\"q".into(), notes: "x\ny".into(), favorite: true, ..Default::default() };
        let back = parse_csv(&to_csv(&[e.clone()]).unwrap()).unwrap();
        assert_eq!(back, vec![e]);
    }

    #[test]
    fn keeps_password_spaces_and_unknown_columns() {
        let v = parse_csv("name,login_password,login_totp,fields\nX, p w ,JBSWY3DP,cpf: 1\n").unwrap();
        assert_eq!(v[0].password, " p w ");
        assert_eq!(v[0].notes, "login_totp: JBSWY3DP\nfields: cpf: 1");
    }

    #[test]
    fn rejects_unknown_header() {
        assert!(parse_csv("foo,bar\n1,2\n").unwrap_err().contains("foo, bar"));
    }
}
