import json
import os.path
from tkinter import *
from tkinter import filedialog, messagebox
from functools import partial
from cryptography.fernet import Fernet
from pymongo import MongoClient

mc = MongoClient('')
db = mc['AlternativeAssessment']
db_users = db['TkUsers']


tmp = list(db_users.find({}))
tmp_dict = dict()
users = list()
for db_user in tmp:
    for user in db_user:
        if user == "_id":
            continue
        tmp_dict[user] = db_user[user]
    if tmp_dict not in users and tmp_dict != {}:
        users.append(tmp_dict)
og = users.copy()

# users = json.load(f)
for user in users:
    if "key" in user:
        user["key"] = bytes(user["key"], "utf-8")
    else:
        user["key"] = Fernet.generate_key()


def gen_key(username):
    key = Fernet.generate_key()
    add_key(username, key)


def add_key(username, key):
    users[username] = key


def save_external_users():
    for u_user in users:
        if "key" not in u_user:
            u_user["key"] = Fernet.generate_key().decode("utf-8")
        if "key" in u_user:
            if isinstance(u_user["key"], bytes):
                u_user["key"] = u_user["key"].decode("utf-8")

    # with open("users.json", "w") as f:
    #     json.dump(users, f)
    list_to_save = list()
    for u_user in users:
        if u_user not in og:
            list_to_save.append(u_user)
    db_users.insert_many(list_to_save)
    print("Saved")


def encrypt(username, file):
    with open(file, "rb") as f:
        data = f.read()
    key = username["key"]
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(file, "wb") as f:
        f.write(encrypted)


def decrypt(username, file):
    with open(file, "rb") as f:
        data = f.read()
    key = username["key"]
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(file, "wb") as f:
        f.write(decrypted)


def validateLogin(username, password, internal_users: dict):
    # getting form data
    with open("loggedin.txt", "w"):
        pass
    uname = username.get()
    pwd = password.get()
    # applying empty validation
    if uname == '' or pwd == '':
        messagebox.showerror(title="Empty Fields", message="Please fill all the fields")
    for i_user in internal_users:
        if i_user["username"] == uname and i_user["password"] == pwd:
            with open("loggedin.txt", "w") as f:
                f.write(uname)
            messagebox.showinfo(title="Success", message="Successfully logged in.")
            return
    messagebox.showerror(title="Invalid Credentials", message="Invalid Credentials")



def register(username, password, internal_users: list):
    for i_user in internal_users:
        if i_user["username"] == username.get():
            messagebox.showerror(title="Username already exists", message="Username already exists.")
            return
    internal_users.append({"username": username.get(), "password": password.get()})
    messagebox.showinfo(title="Success", message="Successfully registered.")
    save_external_users()


class FileManager:
    def __init__(self):
        with open("path.txt", "w"):
            pass
        self.window = Tk()
        # Set window title
        self.window.title('File Encryptor')

        self.window.geometry("500x500")

        self.window.config(background="white")

        self.label_file_explorer = Label(self.window,
                                         text="File Explorer using Tkinter",
                                         width=100, height=4,
                                         fg="blue")

        self.button_explore = Button(self.window,
                                     text="Browse Files",
                                     command=self.browseFiles)

        self.button_exit = Button(self.window,
                                  text="Exit",
                                  command=exit)

        self.label_file_explorer.grid(column=1, row=5)

        self.button_explore.grid(column=1, row=6)

        self.button_exit.grid(column=1, row=7)

    def main(self):
        self.place_widgets()
        self.window.mainloop()

    def place_widgets(self):
        Label(self.window, text="User Name").grid(row=0, column=0)
        username = StringVar()
        Entry(self.window, textvariable=username).grid(row=0, column=1)
        Label(self.window, text="Password").grid(row=1, column=0)
        password = StringVar()
        Entry(self.window, textvariable=password, show='*').grid(row=1, column=1)
        validate = partial(validateLogin, username, password, users)
        Button(self.window, text="Login", command=validate).grid(row=2, column=1)
        reg = partial(register, username, password, users)
        Button(self.window, text="Register", command=reg).grid(row=3, column=1)
        Label(self.window, text="Select A File: ").grid(row=4, column=1)


    def browseFiles(self):
        filename = filedialog.askopenfilename(initialdir="/",
                                              title="Select a File",
                                              filetypes=(("Text files",
                                                          "*.txt*"),
                                                         ("all files",
                                                          "*.*")))

        # Change label contents
        self.label_file_explorer.configure(text="File Opened: " + filename)
        with open("path.txt", "w") as file:
            file.write(filename)

        enc = partial(self.load_enc_path)
        Button(self.window, text="Encrypt", command=enc).grid(row=4, column=0)
        dec = partial(self.load_dec_path)
        Button(self.window, text="Decrypt", command=dec).grid(row=5, column=0)

    def load_enc_path(self):
        with open("loggedin.txt", "r") as t:
            logged = t.read()
        o_user = {}
        for i in users:
            if logged == i["username"] and logged != "":
                o_user = i
        if o_user == {}:
            messagebox.showerror(title="Error", message="You are not logged in!")
            return
        with open("path.txt", "r") as t:
            path = t.read()
            encrypt(o_user, path)
            messagebox.showinfo(title="Success", message="File Encrypted!")

    def load_dec_path(self):
        with open("loggedin.txt", "r") as t:
            logged = t.read()
        o_user = {}
        for i in users:
            if logged == i["username"] and logged != "":
                o_user = i
        if o_user == {}:
            messagebox.showerror(title="Error", message="You are not logged in!")
            return
        with open("path.txt", "r") as file:
            path = file.read()
            decrypt(o_user, path)
        messagebox.showinfo(title="Success", message="Successfully Decrypted.")
