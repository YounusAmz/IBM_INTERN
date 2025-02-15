import tkinter as tk
from tkinter import filedialog, messagebox
from stegano import lsb
import hashlib
import os

def browse_image():
    filepath = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
    if filepath and os.path.exists(filepath):  # Ensure file exists
        entry_image.delete(0, tk.END)
        entry_image.insert(0, filepath)
    else:
        messagebox.showerror("Error", "Selected file does not exist!")

def decrypt_message():
    image_path = entry_image.get()
    password = entry_password.get()

    if not os.path.exists(image_path):
        messagebox.showerror("Error", "Image file not found! Please select a valid image.")
        return
    
    if image_path and password:
        try:
            encrypted_message = lsb.reveal(image_path)
            if encrypted_message:
                stored_hash, secret_message = encrypted_message.split(":", 1)
                input_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if stored_hash == input_hash:
                    messagebox.showinfo("Decryption Successful", f"Secret Message: {secret_message}")
                else:
                    messagebox.showerror("Error", "Incorrect password!")
            else:
                messagebox.showerror("Error", "No hidden message found.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Warning", "Please select an image and enter a password.")

# GUI Setup
root = tk.Tk()
root.title("Image Decryption with Password")

# Image Input
label_image = tk.Label(root, text="Select an encrypted image:")
label_image.pack()
entry_image = tk.Entry(root, width=50)
entry_image.pack()
button_browse = tk.Button(root, text="Browse", command=browse_image)
button_browse.pack()

# Password Input
label_password = tk.Label(root, text="Enter the decryption password:")
label_password.pack()
entry_password = tk.Entry(root, width=50, show="*")
entry_password.pack()

# Decrypt Button
button_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message)
button_decrypt.pack()

root.mainloop()
