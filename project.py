import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import secure_backend as backend
import os, sys

current_user = None
current_role = None

# ---------- UI FUNCTIONS ---------- #

def logout():
    main.destroy()
    restart_login()

def restart_login():
    python = sys.executable
    os.execl(python, python, *sys.argv)


# ---------- MAIN UI ---------- #

def open_main(username, role):
    global main, current_user, current_role
    current_user = username
    current_role = role

    login_win.destroy()
    main = tk.Tk()
    main.title("Secure System Call Interface - APRA Project")
    main.geometry("950x650")
    main.config(bg="#1A1A1A")

    notebook = ttk.Notebook(main)
    notebook.pack(expand=True, fill="both")

    # -------------------------------- TAB 1 - COMMANDS -------------------------------- #
    cmd_tab = tk.Frame(notebook, bg="#1A1A1A")
    notebook.add(cmd_tab, text="Secure Commands")

    tk.Label(cmd_tab, text=f"Logged in as: {username} ({role})",
             font=("Arial", 12), fg="white", bg="#1A1A1A").pack(pady=5)

    entry_cmd = tk.Entry(cmd_tab, width=50, font=("Arial", 12))
    entry_cmd.pack(pady=10)

    txt_output = tk.Text(cmd_tab, width=100, height=22, bg="#222", fg="white")
    txt_output.pack(pady=10)

    def execute_cmd():
        cmd = entry_cmd.get()
        if not cmd:
            return
        result = backend.secure_execute(username, cmd)
        txt_output.delete(1.0, tk.END)
        txt_output.insert(tk.END, result)

    tk.Button(cmd_tab, text="Run Command", command=execute_cmd,
              bg="#006400", fg="white", width=18).pack(pady=5)

    tk.Button(cmd_tab, text="Logout", command=logout, bg="#B30000", fg="white").pack(pady=8)


    # -------------------------------- TAB 2 - HISTORY -------------------------------- #
    hist_tab = tk.Frame(notebook, bg="#1A1A1A")
    notebook.add(hist_tab, text="Execution History")

    txt_history = tk.Text(hist_tab, width=110, height=28, bg="#222", fg="white")
    txt_history.pack(pady=10)

    def load_history():
        txt_history.delete(1.0, tk.END)
        for row in backend.get_history():
            txt_history.insert(tk.END, f"{row}\n")

    tk.Button(hist_tab, text="Refresh History",
              command=load_history, bg="blue", fg="white").pack()


    # -------------------------------- TAB 3 - POLICY EDITOR (Admin Only) ---------------- #
    if role == "admin":
        pol_tab = tk.Frame(notebook, bg="#1A1A1A")
        notebook.add(pol_tab, text="Policy Editor")

        pol_text = tk.Text(pol_tab, width=110, height=28, bg="#222", fg="white")
        pol_text.pack(pady=10)

        try:
            with open("policies.json", "r") as f:
                pol_text.insert(tk.END, f.read())
        except:
            pol_text.insert(tk.END, "Error Loading Policy")

        def save_policy():
            try:
                text = pol_text.get(1.0, tk.END)
                backend.save_policy_from_text(text)
                messagebox.showinfo("Success", "Policy Updated Successfully!")
            except:
                messagebox.showerror("Error", "Failed to Update")

        tk.Button(pol_tab, text="Save Policy",
                  command=save_policy, bg="green", fg="white").pack()


    # -------------------------------- TAB 4 - USER MANAGEMENT (ADMIN ONLY) ------------- #
    if role == "admin":
        usr_tab = tk.Frame(notebook, bg="#1A1A1A")
        notebook.add(usr_tab, text="User Management")

        tree = ttk.Treeview(usr_tab, columns=("ID", "Username", "Role"),
                            show="headings", height=20)
        tree.pack(pady=10)

        tree.heading("ID", text="ID")
        tree.heading("Username", text="Username")
        tree.heading("Role", text="Role")

        def refresh_users():
            for row in tree.get_children():
                tree.delete(row)
            for row in backend.get_all_users():
                tree.insert("", tk.END, values=row)

        refresh_users()

        tk.Label(usr_tab, text="Username:", fg="white", bg="#1A1A1A").pack()
        new_user = tk.Entry(usr_tab)
        new_user.pack()

        tk.Label(usr_tab, text="Password:", fg="white", bg="#1A1A1A").pack()
        new_pass = tk.Entry(usr_tab, show="*")
        new_pass.pack()

        tk.Label(usr_tab, text="Role:", fg="white", bg="#1A1A1A").pack()
        role_box = ttk.Combobox(usr_tab, values=["user", "admin"])
        role_box.pack()
        role_box.set("user")

        def add_user():
            u = new_user.get()
            p = new_pass.get()
            r = role_box.get()
            ok, msg = backend.create_user(u, p, r)
            messagebox.showinfo("Status", msg)
            refresh_users()

        tk.Button(usr_tab, text="Add User", command=add_user,
                  bg="green", fg="white").pack(pady=5)

        def delete_user():
            item = tree.selection()
            if not item:
                return
            uid = tree.item(item)["values"][0]
            backend.delete_user(uid)
            refresh_users()

        tk.Button(usr_tab, text="Delete User",
                  bg="red", fg="white", command=delete_user).pack(pady=5)


    # -------------------------------- TAB 5 - ABOUT -------------------------------- #
    about_tab = tk.Frame(notebook, bg="#1A1A1A")
    notebook.add(about_tab, text="About Project")

    tk.Label(
        about_tab,
        text="Secure System Call Interface\nDeveloped By: APRA",
        fg="cyan",
        bg="#1A1A1A",
        font=("Arial", 16, "bold")
    ).pack(pady=50)

    tk.Label(
        about_tab,
        text="Under Guidance of: Your College Faculty\nCollege Name: Will Be Added To Report",
        fg="white",
        bg="#1A1A1A",
        font=("Arial", 12)
    ).pack(pady=10)

    main.mainloop()


# ---------------------- LOGIN SCREEN ---------------------- #

def login():
    uname = entry_user.get()
    pwd = entry_pass.get()
    role = backend.authenticate(uname, pwd)
    if role:
        open_main(uname, role)
    else:
        messagebox.showerror("Error", "Invalid Credentials!")


login_win = tk.Tk()
login_win.title("Login - Secure System Call")
login_win.geometry("350x220")
login_win.config(bg="#1A1A1A")

tk.Label(login_win, text="Username:", fg="white", bg="#1A1A1A").pack(pady=5)
entry_user = tk.Entry(login_win)
entry_user.pack()

tk.Label(login_win, text="Password:", fg="white", bg="#1A1A1A").pack(pady=5)
entry_pass = tk.Entry(login_win, show="*")
entry_pass.pack()

tk.Button(login_win, text="Login", bg="orange",
          command=login).pack(pady=10)

login_win.mainloop()
# Admin Apra
# Password = 123@123
