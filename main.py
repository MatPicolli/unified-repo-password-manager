# repo unifier/main.py#L1-260
import base64
import hashlib
import io
import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import keyring
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fuzzywuzzy import fuzz
from github import Github, GithubException

KEYRING_SERVICE = "PasswordManagerApp"


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador de Senhas - GitHub Encrypted")
        self.root.geometry("1100x700")

        # Configurações do GitHub
        self.github_token = keyring.get_password(KEYRING_SERVICE, "github_token") or ""
        self.repo_name = (
            keyring.get_password(KEYRING_SERVICE, "repo_name")
            or "MatPicolli/personal-data-bank"
        )
        self.file_path = os.getenv("FILE_PATH", "passwords.csv.enc")

        self.github_repo = None
        self.fernet = None
        # Definindo as colunas baseadas no exemplo senhas.csv
        self.columns = ["Serviço", "Usuário", "Senha", "E-mail", "Notas"]
        self.df = pd.DataFrame(columns=self.columns)
        self.df_filtered = self.df.copy()
        self.salt = b"\x12\x84\xef\x99\x1f\x1e\x96\x0c\x83\x8f\x87\xdc\xb9\xba\x8c\x82"
        self.meta_path = "vault_meta.json.enc"
        self.vault_meta = {}  # {filename: {"password_hash": "...", "salt": "..."}}

        self.setup_login_ui()

    def generate_key(self, master_password):
        """Gera uma chave Fernet a partir da senha mestre."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return Fernet(key)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def setup_login_ui(self):
        self.clear_window()
        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="Acesso Seguro GitHub", font=("Arial", 18, "bold")).pack(
            pady=20
        )

        tk.Label(frame, text="GitHub PAT:").pack()
        self.token_entry = tk.Entry(frame, width=50, show="*")
        self.token_entry.insert(0, self.github_token)
        self.token_entry.pack(pady=5)

        tk.Label(frame, text="Repositório:").pack()
        self.repo_entry = tk.Entry(frame, width=50)
        self.repo_entry.insert(0, self.repo_name)
        self.repo_entry.pack(pady=5)

        tk.Label(frame, text="Senha Mestre:").pack()
        self.master_pwd_entry = tk.Entry(frame, show="*", width=50)
        self.master_pwd_entry.pack(pady=5)

        tk.Button(
            frame,
            text="Conectar e Abrir",
            command=self.login,
            bg="#4CAF50",
            fg="white",
            width=30,
            height=2,
        ).pack(pady=20)

    def login(self):
        token = self.token_entry.get()
        repo_name = self.repo_entry.get()
        master_pwd = self.master_pwd_entry.get()

        if not token or not repo_name or not master_pwd:
            messagebox.showerror("Erro", "Preencha todos os campos!")
            return

        try:
            g = Github(token)
            self.github_repo = g.get_repo(repo_name)
            self.fernet = self.generate_key(master_pwd)
            self.github_token = token
            self.repo_name = repo_name

            # Salva credenciais de forma segura no sistema operacional
            keyring.set_password(KEYRING_SERVICE, "github_token", token)
            keyring.set_password(KEYRING_SERVICE, "repo_name", repo_name)

            self.load_vault_meta()
            self.setup_file_selector()
        except Exception as e:
            messagebox.showerror(
                "Erro", f"Falha na conexão ou senha incorreta:\n{str(e)}"
            )

    def hash_extra_password(self, password, salt=None):
        """Gera um hash seguro para a senha extra do banco."""
        if salt is None:
            salt = os.urandom(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return base64.b64encode(h).decode(), base64.b64encode(salt).decode()

    def verify_extra_password(self, password, stored_hash, stored_salt):
        """Verifica se a senha extra está correta."""
        salt = base64.b64decode(stored_salt)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return base64.b64encode(h).decode() == stored_hash

    def load_vault_meta(self):
        """Carrega metadados dos bancos (senhas extras) do GitHub."""
        try:
            file_content = self.github_repo.get_contents(self.meta_path)
            encrypted_data = file_content.decoded_content
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.vault_meta = json.loads(decrypted_data.decode())
        except GithubException as e:
            if e.status == 404:
                self.vault_meta = {}
            else:
                raise e
        except Exception:
            self.vault_meta = {}

    def save_vault_meta(self):
        """Salva metadados dos bancos no GitHub."""
        try:
            encrypted_data = self.fernet.encrypt(json.dumps(self.vault_meta).encode())
            try:
                contents = self.github_repo.get_contents(self.meta_path)
                self.github_repo.update_file(
                    self.meta_path,
                    "Update vault metadata",
                    encrypted_data,
                    contents.sha,
                )
            except GithubException:
                self.github_repo.create_file(
                    self.meta_path, "Initial vault metadata", encrypted_data
                )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar metadados:\n{str(e)}")

    def list_encrypted_files(self):
        """Lista todos os arquivos .csv.enc no repositório."""
        try:
            contents = self.github_repo.get_contents("")
            files = []
            for item in contents:
                if item.name.endswith(".csv.enc"):
                    files.append(item.name)
            return sorted(files)
        except Exception:
            return []

    def setup_file_selector(self):
        """Tela de seleção de arquivo de senhas."""
        self.clear_window()

        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            frame, text="Selecione um Banco de Senhas", font=("Arial", 18, "bold")
        ).pack(pady=20)

        # Lista de arquivos
        files = self.list_encrypted_files()

        listbox_frame = tk.Frame(frame)
        listbox_frame.pack(pady=10)

        self.file_listbox = tk.Listbox(
            listbox_frame, width=50, height=10, font=("Arial", 12)
        )
        scrollbar = tk.Scrollbar(
            listbox_frame, orient="vertical", command=self.file_listbox.yview
        )
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        self.file_listbox.pack(side="left", fill="both")
        scrollbar.pack(side="right", fill="y")

        for f in files:
            # Mostra o nome sem a extensão .csv.enc
            name = f.replace(".csv.enc", "")
            has_password = f in self.vault_meta
            display = f"🔒 {name}" if has_password else f"    {name}"
            self.file_listbox.insert("end", display)

        # Duplo clique para abrir
        self.file_listbox.bind("<Double-1>", lambda e: self.open_selected_file())
        self.file_listbox.bind("<Return>", lambda e: self.open_selected_file())

        # Botões
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=15)

        tk.Button(
            btn_frame,
            text="📂 Abrir",
            command=self.open_selected_file,
            bg="#4CAF50",
            fg="white",
            width=15,
            height=2,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text="➕ Novo Banco",
            command=self.create_new_file,
            bg="#2196F3",
            fg="white",
            width=15,
            height=2,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text="🔙 Voltar",
            command=self.setup_login_ui,
            width=15,
            height=2,
        ).pack(side="left", padx=5)

    def open_selected_file(self):
        """Abre o arquivo selecionado na lista."""
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um banco de senhas.")
            return

        display_name = self.file_listbox.get(selection[0]).strip()
        # Remove o ícone de cadeado se existir
        name = display_name.replace("🔒 ", "").strip()
        self.file_path = f"{name}.csv.enc"

        # Verifica se o banco tem senha extra
        if self.file_path in self.vault_meta:
            self._ask_extra_password()
        else:
            self.load_data_from_github()
            self.setup_main_ui()

    def _ask_extra_password(self):
        """Pede a senha extra para abrir um banco protegido."""
        win = tk.Toplevel(self.root)
        win.title("Banco Protegido")
        win.geometry("400x180")
        win.grab_set()

        tk.Label(
            win, text="🔒 Este banco requer senha extra:", font=("Arial", 12)
        ).pack(pady=(20, 5))
        pwd_entry = tk.Entry(win, show="*", width=40, font=("Arial", 12))
        pwd_entry.pack(pady=5)
        pwd_entry.focus_set()

        def confirm(event=None):
            password = pwd_entry.get().strip()
            if not password:
                messagebox.showwarning("Aviso", "Digite a senha.")
                return

            meta = self.vault_meta[self.file_path]
            if self.verify_extra_password(
                password, meta["password_hash"], meta["salt"]
            ):
                win.destroy()
                self.load_data_from_github()
                self.setup_main_ui()
            else:
                messagebox.showerror("Erro", "Senha extra incorreta!")

        pwd_entry.bind("<Return>", confirm)
        tk.Button(
            win,
            text="Desbloquear",
            command=confirm,
            bg="#4CAF50",
            fg="white",
            width=15,
            height=2,
        ).pack(pady=15)

    def create_new_file(self):
        """Cria um novo banco de senhas."""
        win = tk.Toplevel(self.root)
        win.title("Novo Banco de Senhas")
        win.geometry("400x300")
        win.grab_set()

        tk.Label(win, text="Nome do novo banco:", font=("Arial", 12)).pack(pady=(20, 5))
        name_entry = tk.Entry(win, width=40, font=("Arial", 12))
        name_entry.pack(pady=5)
        tk.Label(
            win, text="(ex: trabalho, pessoal, streaming)", font=("Arial", 9), fg="gray"
        ).pack()

        tk.Label(win, text="Senha extra (opcional):", font=("Arial", 12)).pack(
            pady=(15, 5)
        )
        extra_pwd_entry = tk.Entry(win, show="*", width=40, font=("Arial", 12))
        extra_pwd_entry.pack(pady=5)
        tk.Label(
            win,
            text="Deixe vazio para não proteger com senha extra",
            font=("Arial", 9),
            fg="gray",
        ).pack()

        def confirm():
            name = name_entry.get().strip()
            if not name:
                messagebox.showwarning("Aviso", "Digite um nome para o banco.")
                return

            self.file_path = f"{name}.csv.enc"
            self.df = pd.DataFrame(columns=self.columns)

            # Salva senha extra se definida
            extra_pwd = extra_pwd_entry.get().strip()
            if extra_pwd:
                pwd_hash, salt = self.hash_extra_password(extra_pwd)
                self.vault_meta[self.file_path] = {
                    "password_hash": pwd_hash,
                    "salt": salt,
                }
                self.save_vault_meta()

            win.destroy()
            self.setup_main_ui()

        tk.Button(
            win,
            text="Criar",
            command=confirm,
            bg="#4CAF50",
            fg="white",
            width=15,
            height=2,
        ).pack(pady=15)

    def load_data_from_github(self):
        try:
            file_content = self.github_repo.get_contents(self.file_path)
            encrypted_data = file_content.decoded_content
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.df = pd.read_csv(io.BytesIO(decrypted_data))

            # Garantir colunas
            for col in self.columns:
                if col not in self.df.columns:
                    self.df[col] = ""
            self.df = self.df[self.columns]
        except GithubException as e:
            if e.status == 404:
                messagebox.showinfo(
                    "Info", "Arquivo não encontrado. Iniciando novo banco."
                )
                self.df = pd.DataFrame(columns=self.columns)
            else:
                raise e
        except Exception:
            raise Exception("Erro na descriptografia. Verifique a senha mestre.")

    def save_to_github(self):
        try:
            csv_buffer = io.StringIO()
            self.df.to_csv(csv_buffer, index=False)
            encrypted_data = self.fernet.encrypt(csv_buffer.getvalue().encode())

            try:
                contents = self.github_repo.get_contents(self.file_path)
                self.github_repo.update_file(
                    self.file_path,
                    "Update passwords via App",
                    encrypted_data,
                    contents.sha,
                )
            except:
                self.github_repo.create_file(
                    self.file_path, "Initial passwords creation", encrypted_data
                )

            messagebox.showinfo("Sucesso", "Dados sincronizados com o GitHub!")
        except Exception as e:
            messagebox.showerror("Erro ao Salvar", str(e))

    def import_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        try:
            # Importar conforme senhas.csv (sem cabeçalho)
            imported_df = pd.read_csv(
                file_path, header=None, names=self.columns, encoding="latin-1"
            )
            if messagebox.askyesno(
                "Importar", f"Deseja importar {len(imported_df)} registros?"
            ):
                self.df = pd.concat([self.df, imported_df], ignore_index=True)
                self.apply_filter()
        except Exception as e:
            messagebox.showerror("Erro na Importação", f"Erro ao ler arquivo: {e}")

    def setup_main_ui(self):
        self.clear_window()

        # Barra Superior
        top_frame = tk.Frame(self.root, pady=10)
        top_frame.pack(fill="x", padx=10)

        # Botão Voltar e nome do banco atual
        tk.Button(top_frame, text="🔙", command=self.setup_file_selector, width=3).pack(
            side="left", padx=(0, 5)
        )
        current_name = self.file_path.replace(".csv.enc", "")
        tk.Label(top_frame, text=f"📁 {current_name}", font=("Arial", 11, "bold")).pack(
            side="left", padx=(0, 10)
        )

        # Busca Fuzzy
        tk.Label(top_frame, text="🔍 Buscar:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.apply_filter())
        self.search_entry = tk.Entry(top_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side="left", padx=10)

        # Botões
        tk.Button(top_frame, text="➕ Novo", command=self.add_entry).pack(
            side="left", padx=2
        )
        tk.Button(top_frame, text="✏️ Editar", command=self.edit_entry).pack(
            side="left", padx=2
        )
        tk.Button(top_frame, text="❌ Deletar", command=self.delete_entry).pack(
            side="left", padx=2
        )
        tk.Button(
            top_frame,
            text="📥 Importar CSV",
            command=self.import_csv,
            bg="#607D8B",
            fg="white",
        ).pack(side="left", padx=20)
        tk.Button(
            top_frame,
            text="☁️ Salvar no GitHub",
            command=self.save_to_github,
            bg="#2196F3",
            fg="white",
        ).pack(side="right", padx=5)

        # Tabela
        self.tree = ttk.Treeview(self.root, columns=self.columns, show="headings")
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Duplo clique e Enter abrem o registro selecionado
        self.tree.bind("<Double-1>", lambda e: self.edit_entry())
        self.tree.bind("<Return>", lambda e: self.edit_entry())

        self.apply_filter()

    def apply_filter(self):
        query = self.search_var.get().lower()
        if not query:
            self.df_filtered = self.df.copy()
        else:

            def fuzzy_match(row):
                # Combina as colunas para a busca
                search_text = " ".join(
                    [str(val).lower() for val in row.values if pd.notna(val)]
                )
                return (
                    query in search_text or fuzz.partial_ratio(query, search_text) > 75
                )

            mask = self.df.apply(fuzzy_match, axis=1)
            self.df_filtered = self.df[mask]

        self.refresh_tree()

    def refresh_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        for index, row in self.df_filtered.iterrows():
            values = [str(v) if pd.notna(v) else "" for v in row]
            self.tree.insert("", "end", iid=index, values=values)

    def add_entry(self):
        self.entry_window("Novo Registro")

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Selecione um registro para editar.")
            return
        self.entry_window("Editar Registro", int(selected[0]))

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
        if messagebox.askyesno("Confirmar", "Deletar este registro localmente?"):
            self.df = self.df.drop(int(selected[0])).reset_index(drop=True)
            self.apply_filter()

    def entry_window(self, title, index=None):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("500x550")
        win.grab_set()

        entries = {}
        for field in self.columns:
            tk.Label(win, text=field, font=("Arial", 10, "bold")).pack(pady=(10, 0))
            if field == "Notas":
                txt = tk.Text(win, width=50, height=6)
                if index is not None:
                    txt.insert(
                        "1.0",
                        str(self.df.at[index, field])
                        if pd.notna(self.df.at[index, field])
                        else "",
                    )
                txt.pack(pady=5)
                entries[field] = txt
            else:
                ent = tk.Entry(win, width=50)
                if index is not None:
                    ent.insert(
                        0,
                        str(self.df.at[index, field])
                        if pd.notna(self.df.at[index, field])
                        else "",
                    )
                    # Bloqueia edição do Serviço em registros existentes
                    if field == "Serviço":
                        ent.config(state="readonly")
                ent.pack(pady=5)
                entries[field] = ent

        def confirm():
            new_data = {}
            for f in self.columns:
                if f == "Notas":
                    new_data[f] = entries[f].get("1.0", "end-1c").strip()
                else:
                    new_data[f] = entries[f].get().strip()

            if index is not None:
                for f in self.columns:
                    self.df.at[index, f] = new_data[f]
            else:
                self.df = pd.concat(
                    [self.df, pd.DataFrame([new_data])], ignore_index=True
                )

            self.apply_filter()
            win.destroy()

        tk.Button(
            win,
            text="Confirmar",
            command=confirm,
            bg="#4CAF50",
            fg="white",
            width=20,
            height=2,
        ).pack(pady=30)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
