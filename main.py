import base64
import hashlib
import io
import json
import os
import secrets
import string
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk

import keyring
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fuzzywuzzy import fuzz
from github import Github, GithubException

# Importação para criar ZIPs com senha
try:
    import pyzipper
except ImportError:
    pyzipper = None

KEYRING_SERVICE = "PasswordManagerApp"


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gestor de Palavras-passe - GitHub Encrypted")
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

        # As colunas de dados (a Tag fará parte do dado, mas não será uma coluna visual comum)
        self.columns = ["Serviço", "Usuário", "Senha", "E-mail", "Notas", "Tag"]
        self.df = pd.DataFrame(columns=self.columns)
        self.df_filtered = self.df.copy()
        self.salt = b"\x12\x84\xef\x99\x1f\x1e\x96\x0c\x83\x8f\x87\xdc\xb9\xba\x8c\x82"
        self.meta_path = "vault_meta.json.enc"
        self.vault_meta = {}

        # Mapeamento de Cores para as Tags (bg: fundo da linha, flag: cor forte da bandeirola)
        self.default_color_map = {
            "Nenhum": {"bg": "white", "fg": "black", "icon": "⬜", "flag": ""},
            "Vermelho": {
                "bg": "#ffcccc",
                "fg": "black",
                "icon": "🟥",
                "flag": "#e63946",
            },
            "Verde": {"bg": "#ccffcc", "fg": "black", "icon": "🟩", "flag": "#2a9d8f"},
            "Azul": {"bg": "#cce6ff", "fg": "black", "icon": "🟦", "flag": "#4cc9f0"},
            "Amarelo": {
                "bg": "#ffffcc",
                "fg": "black",
                "icon": "🟨",
                "flag": "#e9c46a",
            },
            "Roxo": {"bg": "#e6ccff", "fg": "black", "icon": "🟪", "flag": "#9b5de5"},
        }
        self.color_map = self.default_color_map.copy()

        self.setup_login_ui()

    def create_flag_images(self):
        """Desenha ícones de bandeirola e quadrados do menu em memória para evitar restrições do SO."""
        self.flag_images = {}
        self.menu_images = {}

        for name, config in self.color_map.items():
            color = config.get("flag", "#000000")

            # 1. CRIAR QUADRADOS PARA O MENU (16x16)
            m_img = tk.PhotoImage(width=16, height=16)
            if name == "Nenhum":
                # Desenha apenas uma moldura cinza para a opção "Nenhum"
                for y in range(16):
                    for x in range(16):
                        if x == 0 or x == 15 or y == 0 or y == 15:
                            m_img.put("#cccccc", to=(x, y))
            else:
                # Quadrado perfeitamente colorido
                for y in range(16):
                    for x in range(16):
                        m_img.put(color, to=(x, y))
            self.menu_images[name] = m_img

            # Se for "Nenhum", não precisa de bandeirola na árvore
            if name == "Nenhum":
                continue

            # 2. CRIAR BANDEIROLAS PARA A TREEVIEW (24x24)
            img = tk.PhotoImage(width=24, height=24)

            # Algoritmo de pixel-art para desenhar a bandeira com transparência nativa
            for y in range(24):
                for x in range(24):
                    is_flag = False
                    # Caixa base da bandeirola (Retângulo principal)
                    if 4 <= x <= 20 and 4 <= y <= 20:
                        is_flag = True

                        # Recorte em formato de triângulo (Swallowtail) na parte inferior
                        if y > 14:
                            diff = y - 14
                            if 12 - diff <= x <= 12 + diff:
                                is_flag = False

                        # Furo circular no canto superior direito
                        if (x - 17) ** 2 + (y - 7) ** 2 <= 2.0:
                            is_flag = False

                    # Pinta apenas os pixels que fazem parte da bandeira
                    if is_flag:
                        img.put(color, to=(x, y))

            self.flag_images[name] = img

    def generate_key(self, master_password):
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

        tk.Label(frame, text="Palavra-passe Mestra:").pack()
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

            keyring.set_password(KEYRING_SERVICE, "github_token", token)
            keyring.set_password(KEYRING_SERVICE, "repo_name", repo_name)

            self.load_vault_meta()
            self.setup_file_selector()
        except Exception as e:
            messagebox.showerror(
                "Erro", f"Falha na ligação ou palavra-passe incorreta:\n{str(e)}"
            )

    def hash_extra_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return base64.b64encode(h).decode(), base64.b64encode(salt).decode()

    def verify_extra_password(self, password, stored_hash, stored_salt):
        salt = base64.b64decode(stored_salt)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return base64.b64encode(h).decode() == stored_hash

    def load_vault_meta(self):
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
        self.clear_window()

        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            frame, text="Selecione um Banco de Senhas", font=("Arial", 18, "bold")
        ).pack(pady=20)

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
            name = f.replace(".csv.enc", "")
            # Verifica se o arquivo tem metadados de senha (e não apenas tags)
            has_password = (
                f in self.vault_meta and "password_hash" in self.vault_meta[f]
            )
            display = f"🔒 {name}" if has_password else f"    {name}"
            self.file_listbox.insert("end", display)

        self.file_listbox.bind("<Double-1>", lambda e: self.open_selected_file())
        self.file_listbox.bind("<Return>", lambda e: self.open_selected_file())

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
            btn_frame, text="🔙 Voltar", command=self.setup_login_ui, width=15, height=2
        ).pack(side="left", padx=5)

    def open_selected_file(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um banco de palavras-passe.")
            return

        display_name = self.file_listbox.get(selection[0]).strip()
        name = display_name.replace("🔒 ", "").strip()
        self.file_path = f"{name}.csv.enc"

        # Exige senha apenas se o banco tiver um password_hash registrado
        if (
            self.file_path in self.vault_meta
            and "password_hash" in self.vault_meta[self.file_path]
        ):
            self._ask_extra_password()
        else:
            self.load_data_from_github()
            self.setup_main_ui()

    def _ask_extra_password(self):
        win = tk.Toplevel(self.root)
        win.title("Banco Protegido")
        win.geometry("400x180")
        win.grab_set()

        tk.Label(
            win, text="🔒 Este banco requer palavra-passe extra:", font=("Arial", 12)
        ).pack(pady=(20, 5))
        pwd_entry = tk.Entry(win, show="*", width=40, font=("Arial", 12))
        pwd_entry.pack(pady=5)
        pwd_entry.focus_set()

        def confirm(event=None):
            password = pwd_entry.get().strip()
            if not password:
                messagebox.showwarning("Aviso", "Digite a palavra-passe.")
                return

            meta = self.vault_meta[self.file_path]
            if self.verify_extra_password(
                password, meta["password_hash"], meta["salt"]
            ):
                win.destroy()
                self.load_data_from_github()
                self.setup_main_ui()
            else:
                messagebox.showerror("Erro", "Palavra-passe extra incorreta!")

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

        tk.Label(win, text="Palavra-passe extra (opcional):", font=("Arial", 12)).pack(
            pady=(15, 5)
        )
        extra_pwd_entry = tk.Entry(win, show="*", width=40, font=("Arial", 12))
        extra_pwd_entry.pack(pady=5)
        tk.Label(
            win,
            text="Deixe vazio para não proteger com palavra-passe extra",
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

            extra_pwd = extra_pwd_entry.get().strip()
            if extra_pwd:
                pwd_hash, salt = self.hash_extra_password(extra_pwd)
                if self.file_path not in self.vault_meta:
                    self.vault_meta[self.file_path] = {}
                self.vault_meta[self.file_path]["password_hash"] = pwd_hash
                self.vault_meta[self.file_path]["salt"] = salt
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

            for col in self.columns:
                if col not in self.df.columns:
                    self.df[col] = "Nenhum" if col == "Tag" else ""
            self.df = self.df[self.columns]
        except GithubException as e:
            if e.status == 404:
                messagebox.showinfo(
                    "Info", "Ficheiro não encontrado. Iniciando novo banco."
                )
                self.df = pd.DataFrame(columns=self.columns)
            else:
                raise e
        except Exception:
            raise Exception(
                "Erro na descriptografia. Verifique a palavra-passe mestra."
            )

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
            imported_df = pd.read_csv(file_path, header=None, encoding="latin-1")

            if len(imported_df.columns) == len(self.columns) - 1:
                imported_df.columns = self.columns[:-1]
                imported_df["Tag"] = "Nenhum"
            elif len(imported_df.columns) == len(self.columns):
                imported_df.columns = self.columns
            else:
                messagebox.showerror(
                    "Erro", "O ficheiro CSV não tem um formato compatível."
                )
                return

            # Padroniza valores nulos para strings vazias para uma comparação segura de duplicados
            self.df = self.df.fillna("")
            imported_df = imported_df.fillna("")

            # Salva o comprimento atual para comparar depois
            original_len = len(self.df)

            # Combina os dois DataFrames
            combined_df = pd.concat([self.df, imported_df], ignore_index=True)

            # Remove os registos duplicados exatos (mantém o primeiro que encontrar, ignorando os importados repetidos)
            combined_df = combined_df.drop_duplicates(keep="first", ignore_index=True)

            # Calcula estatísticas da importação
            new_records_count = len(combined_df) - original_len
            ignored_count = len(imported_df) - new_records_count

            # Se não há nada novo
            if new_records_count == 0:
                messagebox.showinfo(
                    "Importação Concluída",
                    "Nenhum registo novo encontrado.\nTodos os dados deste ficheiro já existem no seu banco.",
                )
                return

            # Mensagem personalizada baseada no resultado da filtragem
            msg = f"Deseja importar {new_records_count} novos registos?"
            if ignored_count > 0:
                msg += f"\n\n({ignored_count} registos duplicados foram encontrados e serão ignorados)."

            if messagebox.askyesno("Confirmar Importação", msg):
                self.df = combined_df
                self.apply_filter()

        except Exception as e:
            messagebox.showerror("Erro na Importação", f"Erro ao ler ficheiro: {e}")

    def export_to_zip(self):
        """Exporta os dados em formato CSV dentro de um ZIP protegido por senha aleatória."""
        if pyzipper is None:
            messagebox.showerror(
                "Dependência Ausente",
                "Para exportar em ZIP, por favor, abra o terminal e instale a biblioteca necessária:\n\npip install pyzipper",
            )
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("Arquivo ZIP", "*.zip")],
            title="Exportar Banco de Dados",
            initialfile=self.file_path.replace(".csv.enc", "_exportado.zip"),
        )
        if not file_path:
            return

        try:
            # 1. Gerar senha aleatória (14 caracteres, letras maiúsculas/minúsculas e números)
            alphabet = string.ascii_letters + string.digits
            password = "".join(secrets.choice(alphabet) for _ in range(14))

            # 2. Criar buffer CSV
            csv_buffer = io.StringIO()
            self.df.to_csv(csv_buffer, index=False)
            csv_bytes = csv_buffer.getvalue().encode("utf-8")

            # 3. Determinar o nome do CSV interno
            inner_filename = self.file_path.replace(".enc", "")

            # 4. Criar o ZIP Criptografado
            with pyzipper.AESZipFile(
                file_path,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(password.encode("utf-8"))
                zf.writestr(inner_filename, csv_bytes)

            # 5. Mostrar o Dialog de bloqueio/temporizador com a senha
            self.show_export_password_dialog(password, file_path)

        except Exception as e:
            messagebox.showerror(
                "Erro na Exportação", f"Ocorreu um erro ao criar o ZIP:\n{str(e)}"
            )

    def show_export_password_dialog(self, password, file_path):
        """Mostra o diálogo de exportação concluída com a senha e temporizador."""
        win = tk.Toplevel(self.root)
        win.title("Exportação Concluída")
        win.geometry("450x250")
        win.grab_set()
        win.protocol(
            "WM_DELETE_WINDOW", lambda: None
        )  # Impede de fechar pelo 'X' até o timer acabar

        tk.Label(
            win,
            text="✅ Arquivo exportado com sucesso!",
            font=("Arial", 12, "bold"),
            fg="#4CAF50",
        ).pack(pady=(15, 5))

        info_text = f"O arquivo foi protegido com criptografia AES.\nPor segurança, esta será a ÚNICA vez que você verá esta senha.\nCopie-a e guarde-a agora."
        tk.Label(win, text=info_text, justify="center").pack(pady=5)

        pwd_entry = tk.Entry(
            win, font=("Courier", 14, "bold"), justify="center", width=20
        )
        pwd_entry.insert(0, password)
        pwd_entry.config(state="readonly")
        pwd_entry.pack(pady=5)

        def copy_password():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            copy_btn.config(text="✓ Copiado!", fg="#4CAF50")
            win.after(2000, lambda: copy_btn.config(text="📋 Copiar Senha", fg="black"))

        copy_btn = tk.Button(
            win, text="📋 Copiar Senha", command=copy_password, cursor="hand2"
        )
        copy_btn.pack(pady=5)

        btn_ok = tk.Button(
            win, text="OK (5s)", state="disabled", width=15, height=2, bg="#d3d3d3"
        )
        btn_ok.pack(pady=(10, 15))

        # Temporizador
        def count_down(c):
            if c > 0:
                btn_ok.config(text=f"Estou ciente ({c}s)")
                win.after(1000, count_down, c - 1)
            else:
                btn_ok.config(
                    text="OK",
                    state="normal",
                    bg="#2196F3",
                    fg="white",
                    command=win.destroy,
                )
                win.protocol("WM_DELETE_WINDOW", win.destroy)  # Libera o 'X'

        count_down(5)

    def setup_main_ui(self):
        # Carrega as tags customizadas isoladas do banco atual
        self.color_map = self.default_color_map.copy()
        if (
            self.file_path in self.vault_meta
            and "custom_tags" in self.vault_meta[self.file_path]
        ):
            self.color_map.update(self.vault_meta[self.file_path]["custom_tags"])

        self.clear_window()
        self.create_flag_images()  # Garante que as imagens (inclusive customizadas) estão prontas

        top_frame = tk.Frame(self.root, pady=10)
        top_frame.pack(fill="x", padx=10)

        tk.Button(top_frame, text="🔙", command=self.setup_file_selector, width=3).pack(
            side="left", padx=(0, 5)
        )
        current_name = self.file_path.replace(".csv.enc", "")
        tk.Label(top_frame, text=f"📁 {current_name}", font=("Arial", 11, "bold")).pack(
            side="left", padx=(0, 10)
        )

        tk.Label(top_frame, text="🔍 Buscar:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.apply_filter())
        self.search_entry = tk.Entry(top_frame, textvariable=self.search_var, width=15)
        self.search_entry.pack(side="left", padx=(0, 10))

        tk.Label(top_frame, text="Tag:").pack(side="left")
        self.filter_tag_var = tk.StringVar(value="Todas")
        self.filter_tag_var.trace_add("write", lambda *args: self.apply_filter())
        tag_options = ["Todas"] + list(self.color_map.keys())
        self.tag_filter_cb = ttk.Combobox(
            top_frame,
            textvariable=self.filter_tag_var,
            values=tag_options,
            state="readonly",
            width=12,
        )
        self.tag_filter_cb.pack(side="left", padx=(0, 10))

        tk.Button(top_frame, text="🏷️ Gerenciar Tags", command=self.manage_tags).pack(
            side="left", padx=2
        )
        tk.Button(top_frame, text="➕ Novo", command=self.add_entry).pack(
            side="left", padx=2
        )
        tk.Button(top_frame, text="✏️ Editar", command=self.edit_entry).pack(
            side="left", padx=2
        )
        tk.Button(top_frame, text="❌ Apagar", command=self.delete_entry).pack(
            side="left", padx=2
        )

        # Botão de Exportar adicionado aqui
        tk.Button(
            top_frame,
            text="📤 Exportar",
            command=self.export_to_zip,
            bg="#FF9800",
            fg="white",
        ).pack(side="right", padx=5)
        tk.Button(
            top_frame,
            text="☁️ Salvar",
            command=self.save_to_github,
            bg="#2196F3",
            fg="white",
        ).pack(side="right", padx=5)
        tk.Button(
            top_frame,
            text="📥 Importar",
            command=self.import_csv,
            bg="#607D8B",
            fg="white",
        ).pack(side="right", padx=5)

        # Configura as colunas visíveis (esconde a coluna de dados "Tag", pois usaremos a coluna árvore)
        display_cols = ["Serviço", "Usuário", "Senha", "E-mail", "Notas"]

        # O truque do Shift: show="tree headings" ativa a coluna "#0" na esquerda
        self.tree = ttk.Treeview(
            self.root,
            columns=self.columns,
            displaycolumns=display_cols,
            show="tree headings",
        )

        # Configurar a coluna da árvore que vai empurrar o resto e abrigar a bandeirola
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=45, stretch=tk.NO, anchor="center")

        # Configurar as outras colunas de dados
        for col in display_cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        for color_name, styles in self.color_map.items():
            self.tree.tag_configure(
                color_name, background=styles["bg"], foreground=styles["fg"]
            )

        self.tree.bind("<Double-1>", lambda e: self.edit_entry())
        self.tree.bind("<Return>", lambda e: self.edit_entry())
        self.tree.bind("<Button-3>", self.show_tag_menu)

        self.apply_filter()

    def show_tag_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return

        self.tree.selection_set(item_id)

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Definir Tag/Cor:", state="disabled")
        menu.add_separator()

        for color_name in self.color_map.keys():
            # Obtém a imagem colorida que desenhámos na memória
            img = self.menu_images.get(color_name)

            # Adiciona ao menu usando `image` e `compound="left"`
            menu.add_command(
                label=f"  {color_name}",
                image=img,
                compound="left",
                command=lambda c=color_name, i=item_id: self.apply_tag_to_row(i, c),
            )

        menu.post(event.x_root, event.y_root)

    def apply_tag_to_row(self, item_id, color_name):
        index = int(item_id)
        self.df.at[index, "Tag"] = color_name
        self.apply_filter()

    def manage_tags(self):
        win = tk.Toplevel(self.root)
        win.title("Gerenciar Tags")
        win.geometry("350x400")
        win.grab_set()

        tk.Label(
            win,
            text=f"Tags Locais: {self.file_path.replace('.csv.enc', '')}",
            font=("Arial", 12, "bold"),
        ).pack(pady=10)

        listbox = tk.Listbox(win, font=("Arial", 10))
        listbox.pack(fill="both", expand=True, padx=20, pady=5)

        def refresh_list():
            listbox.delete(0, tk.END)
            win.tag_keys = list(self.color_map.keys())
            for tag in win.tag_keys:
                icon = self.color_map[tag].get("icon", "📌")
                listbox.insert(tk.END, f"{icon}  {tag}")

        refresh_list()

        def add_tag():
            name = simpledialog.askstring("Nova Tag", "Nome da nova tag:", parent=win)
            if not name:
                return
            name = name.strip()
            if not name:
                return
            if name in self.color_map or name.lower() == "todas":
                messagebox.showwarning(
                    "Aviso", "Esta tag já existe ou tem um nome reservado!", parent=win
                )
                return

            bg_color = colorchooser.askcolor(
                title="1. Cor de FUNDO da linha", parent=win
            )[1]
            if not bg_color:
                return

            flag_color = colorchooser.askcolor(
                title="2. Cor da BANDEIROLA", parent=win
            )[1]
            if not flag_color:
                return

            new_tag = {"bg": bg_color, "fg": "black", "icon": "📌", "flag": flag_color}
            self.color_map[name] = new_tag

            # Salva no arquivo atual de metadados do repositório
            if self.file_path not in self.vault_meta:
                self.vault_meta[self.file_path] = {}
            if "custom_tags" not in self.vault_meta[self.file_path]:
                self.vault_meta[self.file_path]["custom_tags"] = {}

            self.vault_meta[self.file_path]["custom_tags"][name] = new_tag
            self.save_vault_meta()

            refresh_list()
            self.create_flag_images()
            if hasattr(self, "tag_filter_cb"):
                self.tag_filter_cb["values"] = ["Todas"] + list(self.color_map.keys())
            if hasattr(self, "tree"):
                self.tree.tag_configure(name, background=bg_color, foreground="black")
            self.apply_filter()

        def del_tag():
            sel = listbox.curselection()
            if not sel:
                return
            tag_name = win.tag_keys[sel[0]]

            if tag_name in self.default_color_map:
                messagebox.showwarning(
                    "Aviso",
                    "Não é possível excluir as tags padrão do sistema.",
                    parent=win,
                )
                return

            if messagebox.askyesno(
                "Confirmar", f"Excluir a tag '{tag_name}'?", parent=win
            ):
                del self.color_map[tag_name]

                # Deleta a tag do registro isolado deste banco
                if (
                    self.file_path in self.vault_meta
                    and "custom_tags" in self.vault_meta[self.file_path]
                ):
                    if tag_name in self.vault_meta[self.file_path]["custom_tags"]:
                        del self.vault_meta[self.file_path]["custom_tags"][tag_name]
                        self.save_vault_meta()

                # Remove a tag das linhas que a usavam
                self.df.loc[self.df["Tag"] == tag_name, "Tag"] = "Nenhum"

                refresh_list()
                self.create_flag_images()
                if hasattr(self, "tag_filter_cb"):
                    self.tag_filter_cb["values"] = ["Todas"] + list(
                        self.color_map.keys()
                    )
                    self.filter_tag_var.set("Todas")
                self.apply_filter()

        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="➕ Criar",
            command=add_tag,
            bg="#4CAF50",
            fg="white",
            width=10,
        ).pack(side="left", padx=5)
        tk.Button(
            btn_frame,
            text="❌ Excluir",
            command=del_tag,
            bg="#f44336",
            fg="white",
            width=10,
        ).pack(side="left", padx=5)

    def apply_filter(self):
        query = self.search_var.get().lower()
        tag_filter = getattr(self, "filter_tag_var", None)
        tag_filter_val = tag_filter.get() if tag_filter else "Todas"

        df_temp = self.df.copy()

        # Primeiro filtra pela Tag
        if tag_filter_val != "Todas":
            df_temp = df_temp[df_temp["Tag"] == tag_filter_val]

        # Depois filtra pelo texto (se houver)
        if not query:
            self.df_filtered = df_temp
        else:

            def fuzzy_match(row):
                search_text = " ".join(
                    [str(val).lower() for val in row.values if pd.notna(val)]
                )
                return (
                    query in search_text or fuzz.partial_ratio(query, search_text) > 75
                )

            mask = df_temp.apply(fuzzy_match, axis=1)
            self.df_filtered = df_temp[mask]

        self.refresh_tree()

    def refresh_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        for index, row in self.df_filtered.iterrows():
            values = [str(v) if pd.notna(v) else "" for v in row]

            tag_name = row.get("Tag", "Nenhum")
            if pd.isna(tag_name) or tag_name not in self.color_map:
                tag_name = "Nenhum"

            # Prepara a inserção definindo a cor de fundo (tag) e a imagem da bandeirola
            kwargs = {"values": values, "tags": (tag_name,)}
            img = self.flag_images.get(tag_name)
            if img:
                kwargs["image"] = img  # Coloca a bandeirola no espaço criado à esquerda

            self.tree.insert("", "end", iid=index, **kwargs)

    def add_entry(self):
        self.entry_window("Novo Registo")

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Selecione um registo para editar.")
            return
        self.entry_window("Editar Registo", int(selected[0]))

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
        if messagebox.askyesno("Confirmar", "Apagar este registo localmente?"):
            self.df = self.df.drop(int(selected[0])).reset_index(drop=True)
            self.apply_filter()

    def entry_window(self, title, index=None):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("500x600")
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

            elif field == "Tag":
                tag_var = tk.StringVar()
                cb = ttk.Combobox(
                    win,
                    textvariable=tag_var,
                    values=list(self.color_map.keys()),
                    state="readonly",
                    width=47,
                )

                current_tag = "Nenhum"
                if (
                    index is not None
                    and pd.notna(self.df.at[index, field])
                    and self.df.at[index, field] != ""
                ):
                    current_tag = str(self.df.at[index, field])
                    if current_tag not in self.color_map:
                        current_tag = "Nenhum"

                cb.set(current_tag)
                cb.pack(pady=5)
                entries[field] = cb

            else:
                ent = tk.Entry(win, width=50)
                if index is not None:
                    ent.insert(
                        0,
                        str(self.df.at[index, field])
                        if pd.notna(self.df.at[index, field])
                        else "",
                    )
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
