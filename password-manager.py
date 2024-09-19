from tkinter import *
import tkinter as tk
import random
import string
from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

if not os.path.exists('key.key'):
    generate_key()
    print("The file 'key.key' does not exist.")

password_names = []
passwords = []

lower = string.ascii_lowercase
upper = string.ascii_uppercase
digits = string.digits
symbols = string.punctuation
chars_complete = lower + upper + digits + symbols
chars_no_symbols = lower + upper + digits

# Encryption process
def load_key():
    return open("key.key", "rb").read()

def encrypt_file(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted)

def decrypt_file(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted = file.read()
    decrypted = f.decrypt(encrypted)
    with open(filename, "wb") as file:
        file.write(decrypted)

# Load the encryption key
key = load_key()
filename = "passwords.txt"

def view_passwords_window(view_window):
    if not password_names:
        message_label = tk.Label(view_window, text="You have no saved passwords.")
        message_label.pack()
        return
    
    for i in range(len(password_names)):
        pwd = passwords[i]
        temp_password = password_names[i] + ": " + passwords[i]
        message_label = tk.Label(view_window, text=temp_password)
        message_label.pack()
        
        def copy_to_clipboard(pwd=pwd):
            view_window.clipboard_clear()
            view_window.clipboard_append(pwd)

        copy_button = Button(view_window, text="Copy Password", command=copy_to_clipboard)
        copy_button.pack()
        
        delete_button = Button(view_window, text="Delete Password", command=lambda i=i: delete_password(view_window, i))
        delete_button.pack()

def delete_password(view_window, index):
    # Remove the password from the in-memory lists
    del password_names[index]
    del passwords[index]
    
    # Rewrite the text file without the deleted password
    save_passwords_to_file()
    
    # Close the view passwords window and reopen it to update the view
    view_window.destroy()
    open_view_passwords_window()

def add_password_window(add_window):
    global password_name_entry, password_entry
    
    password_name_label = tk.Label(add_window, text="Enter email/username:")
    password_name_label.pack()
    password_name_entry = tk.Entry(add_window)
    password_name_entry.pack()

    password_label = tk.Label(add_window, text="Enter a password:")
    password_label.pack()
    password_entry = tk.Entry(add_window)
    password_entry.pack()

    # Button to save the password
    save_button = tk.Button(
        add_window,
        text="Save Password",
        command=lambda: save_password(add_window)
    )
    save_button.pack()

def save_password(add_window):
    name = password_name_entry.get()
    password = password_entry.get()
    if name and password:
        password_names.append(name)
        passwords.append(password)
        save_passwords_to_file()  # Save the passwords to the file
        add_window.destroy()
    else:
        error_label = tk.Label(add_window, text="Please complete both fields.", fg="red")
        error_label.pack()

def save_passwords_to_file():
    with open(filename, "w") as file:
        for name, password in zip(password_names, passwords):
            file.write(f"{name}:{password}\n")
    encrypt_file(filename, key)

def read_passwords_from_file():
    try:
        decrypt_file(filename, key)
        with open(filename, "r") as file:
            for line in file:
                name, password = line.strip().split(":")
                password_names.append(name)
                passwords.append(password)
        encrypt_file(filename, key)
    except FileNotFoundError:
        # If the file does not exist, simply continue
        pass

def generate_password_data(generate_window):
    global password_length_entry, var, length, password
    password_length_label = tk.Label(generate_window, text="Enter length (maximum 20 characters):")
    password_length_label.pack()
    password_length_entry = tk.Entry(generate_window)
    password_length_entry.pack()

    var = tk.IntVar()
    checkbox = tk.Checkbutton(generate_window, text="I want my password to have special characters", variable=var)
    checkbox.pack()

    generate_button = tk.Button(
        generate_window,
        text="Generate Password",
        command=lambda: generate_password(generate_window)
    )
    generate_button.pack()

def generate_password(generate_window):
    global error_label

    if 'error_label' in globals():
        error_label.destroy()

    try:
        length = int(password_length_entry.get())
        if length <= 0 or length > 20:
            raise ValueError("Length out of range")
    except ValueError:
        if not password_length_entry.get():
            error_label = tk.Label(generate_window, text="Please enter a length.", fg="red")
        else:
            error_label = tk.Label(generate_window, text="Length out of range. Enter a number between 1 and 20.", fg="red")
        error_label.pack()
        return

    if var.get() == 1:
        password = "".join(random.sample(chars_complete, length))
    else:
        password = "".join(random.sample(chars_no_symbols, length))
    display_password = tk.Label(generate_window, text=password)
    display_password.pack(pady=10)
    
    def copy_to_clipboard():
        generate_window.clipboard_clear()
        generate_window.clipboard_append(password)

    copy_button = Button(generate_window, text="Copy Password", command=copy_to_clipboard)
    copy_button.pack()

def open_add_password_window():
    # Create a secondary window.
    add_window = tk.Toplevel()
    add_window.title("Add Passwords")
    add_window.geometry("300x150")  # Set the window size
    add_password_window(add_window)

def open_view_passwords_window():
    # Create a secondary window.
    view_window = tk.Toplevel()
    view_window.title("View Passwords")
    view_window.geometry("300x100")  # Set the window size
    view_passwords_window(view_window)

def open_generate_password_window():
    # Create a secondary window.
    generate_window = tk.Toplevel()
    generate_window.title("Generate Password")
    generate_password_data(generate_window)

def close_program():
    window.destroy()

# Main window configuration
window = tk.Tk()
window.title("Password Manager")
window.geometry("300x190")  # Set the main window size

read_passwords_from_file()  # Read passwords on startup

# Button to open the add passwords window
add_password_button = tk.Button(
    window,
    text="Add Passwords",
    command=open_add_password_window
)
add_password_button.pack(pady=10)  # Center the button vertically with a margin

# Button to view the passwords
view_passwords_button = tk.Button(
    window,
    text="View My Passwords",
    command=open_view_passwords_window
)
view_passwords_button.pack(pady=10)  # Center the button vertically with a margin

# Button to generate passwords
generate_password_button = tk.Button(
    window,
    text="Generate Password",
    command=open_generate_password_window
)
generate_password_button.pack(pady=10)  # Center the button vertically with a margin

close_button = tk.Button(
    window,
    text="Close",
    command=close_program
)
close_button.pack(pady=10)  # Center the button vertically with a margin

message_label = tk.Label(window, text="")
message_label.pack()

window.mainloop()
