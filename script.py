from tkinter import *
from tkinter import messagebox
import base64
import random
import string

# function to encrypt
def encrypt():
    key = rand_key()
    msg = Msg.get()
    enc = []

    if not (msg and key):
        messagebox.showerror(title="Error", message="Incorrect input string")
        return

    for i in range(len(msg)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(msg[i]) + ord(key_c)) % 256)
        enc.append(enc_c)

    res = base64.urlsafe_b64encode("".join(enc).encode()).decode()

    with open("./message.txt", "w") as f:
        f.write(res)

    with open("./key.txt", "w") as f:
        f.write(key)

    messagebox.showinfo(
        title="Encryption",
        message=f"Encrypted message and the key are saved in the .txt files",
    )

    reset()


# function to decrypt
def decrypt():
    key = Key.get()
    msg = Msg.get()
    dec = []

    try:
        if not (msg and key):
            raise Exception()

        msg = base64.urlsafe_b64decode(msg).decode()
        for i in range(len(msg)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(msg[i]) - ord(key_c)) % 256)
            dec.append(dec_c)

        res = "".join(dec)
        messagebox.showinfo(title="Decryption", message=f"Descypted message: {res}")
    except:
        messagebox.showerror(title="Error", message="Incorrect input string")

    reset()


# function to reset the window
def reset():
    Msg.set("")
    Key.set("")


# function to generate a key
def rand_key():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=4))


# creating root object
root = Tk()

# defining size of window
root.geometry("700x500")

# setting up the title of window
root.title("Message Encryption/Decryption")

title = Frame(root, width=700, relief=SUNKEN)
title.pack()

f1 = Frame(root, width=700, height=100, relief=SUNKEN)
f1.pack()

Label(
    title, font=("helvetica", 40, "bold"), text="SECRET MESSAGING", fg="Black", bd=10
).grid(row=0, column=0)

Msg = StringVar()
Key = StringVar()

# message label
Label(f1, font=("arial", 16, "bold"), text="MESSAGE", bd=12, anchor="w").grid(
    row=1, column=0
)

# message input
Entry(
    f1, font=("arial", 16, "bold"), textvariable=Msg, bd=6, insertwidth=4, bg="white"
).grid(row=1, column=1, pady=20)

# key label
Label(f1, font=("arial", 16, "bold"), text="KEY", bd=12).grid(row=3, column=0, pady=20)

# key input
Entry(
    f1, font=("arial", 16, "bold"), textvariable=Key, bd=6, insertwidth=4, bg="white"
).grid(row=3, column=1)

# encrypt button
Button(
    f1,
    padx=16,
    pady=8,
    bd=6,
    fg="black",
    font=("arial", 16, "bold"),
    width=10,
    text="Encrypt",
    bg="powder blue",
    command=encrypt,
).grid(row=2, column=1, pady=20)

# decrypt button
Button(
    f1,
    padx=16,
    pady=8,
    bd=6,
    fg="black",
    font=("arial", 16, "bold"),
    width=10,
    text="Decrypt",
    bg="powder blue",
    command=decrypt,
).grid(row=4, column=1)

# keeps window alive
root.mainloop()
