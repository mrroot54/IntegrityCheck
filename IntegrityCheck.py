import os
import hashlib
import tkinter as tk
from tkinter import filedialog

class CustomDialog(tk.Toplevel):
    def __init__(self, parent, title, message, is_error=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x200")  # Set default size here

        self.message = message
        self.is_error = is_error

        self.create_widgets()

    def create_widgets(self):
        message_label = tk.Label(self, text=self.message, wraplength=350)
        message_label.pack(pady=20)

        ok_button = tk.Button(self, text="OK", command=self.destroy)
        ok_button.pack(pady=10)

def show_custom_message(title, message, is_error=False):
    dialog = CustomDialog(root, title, message, is_error)
    root.wait_window(dialog)

def calculate_hash(file_path):
    hash_object = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            hash_object.update(chunk)
    hash_value = hash_object.hexdigest()
    return hash_value

def verify_integrity(file_path, original_hash_value):
    computed_hash_value = calculate_hash(file_path)
    if computed_hash_value == original_hash_value:
        show_custom_message("Integrity Verification", "Data integrity verified.")
    else:
        show_custom_message("Integrity Verification", "Data has been tampered with.", is_error=True)

def verify_file():
    def verify():
        file_path = file_path_entry.get()
        original_hash_value = hash_value_entry.get()
        if file_path and original_hash_value:
            verify_integrity(file_path, original_hash_value)
        else:
            show_custom_message("Verification Error", "Please provide both file path and hash value.", is_error=True)

    verify_options_window = tk.Toplevel()
    verify_options_window.title("Verify Hash Options")

    tk.Label(verify_options_window, text="File Path:").grid(row=0, column=0, padx=10, pady=5)
    file_path_entry = tk.Entry(verify_options_window, width=50)
    file_path_entry.grid(row=0, column=1, padx=10, pady=5)

    browse_button = tk.Button(verify_options_window, text="Browse", command=lambda: file_path_entry.insert(tk.END, filedialog.askopenfilename()))
    browse_button.grid(row=0, column=2, padx=10, pady=5)

    tk.Label(verify_options_window, text="Original Hash Value:").grid(row=1, column=0, padx=10, pady=5)
    hash_value_entry = tk.Entry(verify_options_window, width=50)
    hash_value_entry.grid(row=1, column=1, padx=10, pady=5)

    verify_button = tk.Button(verify_options_window, text="Verify", command=verify)
    verify_button.grid(row=2, column=1, padx=10, pady=10)

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        hash_value = calculate_hash(file_path)
        result_text.set(f"Hash of {file_path}: {hash_value}")
        save_hash_to_file(file_path, hash_value)

def save_hash_to_file(file_path, hash_value):
    directory = os.path.dirname(file_path)
    hash_file_path = os.path.join(directory, 'hash.txt')
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(hash_value)
    show_custom_message("Hash Saved", f"Hash saved to {hash_file_path}")

def main():
    global root, result_text  # Declare root and result_text as global variables
    
    root = tk.Tk()
    root.title("SHA-256 Hash Tool")

    result_text = tk.StringVar()  # Initialize result_text as a Tkinter StringVar
    result_label = tk.Label(root, textvariable=result_text)
    result_label.pack(pady=20)

    create_button = tk.Button(root, text="Create Hash", command=browse_file)
    create_button.pack(pady=10)

    verify_button = tk.Button(root, text="Verify Hash", command=verify_file)
    verify_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
