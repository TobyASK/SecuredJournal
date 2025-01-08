
import os
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet

# === Gestion du chiffrement ===
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

# === Système de mot de passe ===
def set_password():
    password = simpledialog.askstring("Mot de passe", "Créez un mot de passe :", show="*")
    if password:
        encrypted_password = encrypt_message(password)
        with open("password.enc", "wb") as password_file:
            password_file.write(encrypted_password)
        messagebox.showinfo("Succès", "Mot de passe créé avec succès !")

def verify_password():
    if not os.path.exists("password.enc"):
        set_password()

    with open("password.enc", "rb") as password_file:
        encrypted_password = password_file.read()

    for _ in range(3):
        password = simpledialog.askstring("Connexion", "Entrez votre mot de passe :", show="*")
        if password and decrypt_message(encrypted_password) == password:
            messagebox.showinfo("Succès", "Connexion réussie !")
            return True
        else:
            messagebox.showwarning("Erreur", "Mot de passe incorrect.")

    messagebox.showerror("Échec", "Trois tentatives échouées. Application verrouillée.")
    exit()

# === Gestion des entrées du journal ===
def add_entry():
    entry = simpledialog.askstring("Nouvelle entrée", "Écrivez votre entrée :")
    if entry:
        encrypted_entry = encrypt_message(entry)
        with open("journal.enc", "ab") as journal_file:
            journal_file.write(encrypted_entry + b"\n")
        messagebox.showinfo("Succès", "Entrée ajoutée avec succès !")

def read_entries():
    if not os.path.exists("journal.enc"):
        messagebox.showinfo("Informations", "Aucune entrée disponible.")
        return

    with open("journal.enc", "rb") as journal_file:
        entries = journal_file.readlines()

    display_text = ""
    for encrypted_entry in entries:
        display_text += "- " + decrypt_message(encrypted_entry.strip()) + "\n"

    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, display_text)

def export_entries():
    if not os.path.exists("journal.enc"):
        messagebox.showinfo("Informations", "Aucune entrée disponible.")
        return

    with open("journal.enc", "rb") as journal_file:
        entries = journal_file.readlines()

    with open("journal_export.txt", "w") as export_file:
        for encrypted_entry in entries:
            export_file.write(decrypt_message(encrypted_entry.strip()) + "\n")

    messagebox.showinfo("Succès", "Entrées exportées dans 'journal_export.txt'.")

# === Interface graphique ===
def main():
    generate_key()
    if verify_password():
        root = tk.Tk()
        root.title("Journal Personnel Sécurisé")

        frame = tk.Frame(root)
        frame.pack(pady=20)

        tk.Button(frame, text="Ajouter une entrée", command=add_entry).pack(side="left", padx=10)
        tk.Button(frame, text="Lire les entrées", command=read_entries).pack(side="left", padx=10)
        tk.Button(frame, text="Exporter les entrées", command=export_entries).pack(side="left", padx=10)

        global text_widget
        text_widget = tk.Text(root, wrap="word", width=50, height=15)
        text_widget.pack(pady=20)

        root.mainloop()

if __name__ == "__main__":
    main()
