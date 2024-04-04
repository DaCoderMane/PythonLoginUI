import tkinter as tk
from tkinter import messagebox as msgbox
import sqlite3
import hashlib

# Create SQLite database and table if not exists
conn = sqlite3.connect('logins.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS logins
             (username TEXT, password TEXT)''')
conn.commit()

def validate_login(username, password):
    # Check if provided username and password match default admin credentials
    hashed_username = hashlib.sha256(username.encode()).hexdigest()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if (hashed_username == "c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f" and
            hashed_password == "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"):
        return True

    # Check if provided username and password match any entry in the database
    c.execute("SELECT * FROM logins WHERE username=? AND password=?", (username, password))
    result = c.fetchone()
    if result:
        return True

    return False


def show_success_window():
    success_window = tk.Toplevel(root)
    success_window.title("Login Successful")
    success_label = tk.Label(success_window, text="You have successfully logged in!", font=("First Grader", 12))
    success_label.pack(pady=20)
    success_button = tk.Button(success_window, text="OK", command=success_window.destroy, width=10, font=("First Grader", 12))
    success_button.pack(pady=10)

def LogOutSuccesful():
    LogOutSuccesfulWindow = tk.Toplevel(root)
    LogOutSuccesfulWindow.title("Login Error")
    LogOutSuccesfulWindow_label = tk.Label(LogOutSuccesfulWindow, text="You have successfully logged out!", font=("First Grader", 12))
    LogOutSuccesfulWindow_label.pack(pady=20)
    LogOutSuccesfulWindow_button = tk.Button(LogOutSuccesfulWindow, text="OK", command=LogOutSuccesfulWindow.destroy, width=10, font=("First Grader", 12))
    LogOutSuccesfulWindow_button.pack(pady=10)

def show_error_window():
    error_window = tk.Toplevel(root)
    error_window.title("Login Error")
    error_label = tk.Label(error_window, text="Invalid username or password.", font=("First Grader", 12), wraplength=300)
    error_label.pack(pady=20)
    error_button = tk.Button(error_window, text="OK", command=error_window.destroy, width=10, font=("First Grader", 12))
    error_button.pack(pady=10)

def handle_login_click():
    username = username_entry.get()
    password = password_entry.get()

    if validate_login(username, password):
        show_success_window()
        # Clear the entry fields
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        login_button.config(state=tk.DISABLED) # Disable login button
        add_button.config(state=tk.NORMAL)  # Enable add button
        delete_button.config(state=tk.NORMAL)  # Enable delete button
        display_button.config(state=tk.NORMAL)  # Enable display button
        logout_button.config(state=tk.NORMAL)  # Enable logout button
    else:
        show_error_window()
        # Clear only the password field
        password_entry.delete(0, tk.END)

def logout():
    confirm = msgbox.askyesno("Confirmation", "Are you sure you want to logout?")
    if confirm:
        # Clear the entry fields
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        # Disable add, delete, and display buttons
        add_button.config(state=tk.DISABLED)
        delete_button.config(state=tk.DISABLED)
        display_button.config(state=tk.DISABLED)
        # Enable the login button and disable the logout button
        login_button.config(state=tk.NORMAL)
        logout_button.config(state=tk.DISABLED)
        LogOutSuccesful()

def add_entry():
    username = username_entry.get()
    password = password_entry.get()

    # Insert username and password into the database
    c.execute("INSERT INTO logins VALUES (?, ?)", (username, password))
    conn.commit()
    msgbox.showinfo("Success", "Entry added successfully!")

def delete_entry():
    username = username_entry.get()
    password = password_entry.get()

    # Delete username and password from the database
    c.execute("DELETE FROM logins WHERE username=? AND password=?", (username, password))
    conn.commit()
    msgbox.showinfo("Success", "Entry deleted successfully!")

def display_entries():
    entries_window = tk.Toplevel(root)
    entries_window.title("Entries")

    # Fetch all entries from the database
    c.execute("SELECT * FROM logins")
    entries = c.fetchall()

    for index, entry in enumerate(entries, start=1):
        entry_text = f"Username: {entry[0]}, Password: {entry[1]}"
        entry_label = tk.Label(entries_window, text=entry_text, font=("First Grader", 12))
        entry_label.pack()

root = tk.Tk()
root.title("Advanced Login UI")
root.geometry("400x300+500+200")
root.configure(bg="#f0f0f0")  # Set background color

frame = tk.Frame(root, bg="#f0f0f0")  # Add frame with background color
frame.pack(pady=20)

username_label = tk.Label(frame, text="Username:", bg="#f0f0f0", font=("First Grader", 12))
username_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

username_entry = tk.Entry(frame, font=("First Grader", 12))
username_entry.grid(row=0, column=1, padx=10, pady=5)

password_label = tk.Label(frame, text="Password:", bg="#f0f0f0", font=("First Grader", 12))
password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

password_entry = tk.Entry(frame, show="*", font=("First Grader", 12))
password_entry.grid(row=1, column=1, padx=10, pady=5)

login_button = tk.Button(frame, text="Login", command=handle_login_click, width=10, font=("First Grader", 12))
login_button.grid(row=2, column=0, pady=10, padx=5)

logout_button = tk.Button(frame, text="Logout", command=logout, width=10, font=("First Grader", 12), state=tk.DISABLED)
logout_button.grid(row=2, column=1, pady=10, padx=5)

add_button = tk.Button(frame, text="Add Entry", command=add_entry, width=10, font=("First Grader", 12), state=tk.DISABLED)
add_button.grid(row=3, column=0, padx=10, pady=5)

delete_button = tk.Button(frame, text="Delete Entry", command=delete_entry, width=12, font=("First Grader", 12), state=tk.DISABLED)
delete_button.grid(row=3, column=1, padx=10, pady=5)

display_button = tk.Button(frame, text="Display Entries", command=display_entries, width=15, font=("First Grader", 12), state=tk.DISABLED)
display_button.grid(row=4, columnspan=2, pady=10)

root.mainloop()
