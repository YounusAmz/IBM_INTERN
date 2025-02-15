import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from stegano import lsb
import hashlib
import os

def browse_image():
    filepath = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if filepath and os.path.exists(filepath):  # Ensure the file exists
        entry_image.delete(0, tk.END)
        entry_image.insert(0, filepath)
    else:
        messagebox.showerror("Error", "Selected file does not exist!")

def convert_to_png(image_path):
    """ Converts JPG/JPEG images to PNG format for compatibility with steganography. """
    img = Image.open(image_path)
    new_path = image_path.rsplit(".", 1)[0] + ".png"
    img.convert("RGB").save(new_path, "PNG")
    return new_path

def encrypt_message():
    message = entry_message.get()
    image_path = entry_image.get()
    password = entry_password.get()
    
    if not os.path.exists(image_path):
        messagebox.showerror("Error", "Image file not found! Please select a valid image.")
        return

    if message and image_path and password:
        try:
            # Convert to PNG if the selected file is JPG/JPEG
            if image_path.lower().endswith((".jpg", ".jpeg")):
                image_path = convert_to_png(image_path)

            # Hash the password for security
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            combined_message = f"{hashed_password}:{message}"

            # Hide message inside the image
            secret_image = lsb.hide(image_path, combined_message)
            
            # Save encrypted image
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
            if save_path:
                secret_image.save(save_path)
                messagebox.showinfo("Success", f"Message encrypted and saved as {save_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Warning", "Please select an image, enter a message, and set a password.")

# GUI Setup
root = tk.Tk()
root.title("Image Encryption with Password")

# Message Input
label_message = tk.Label(root, text="Enter your secret message:")
label_message.pack()
entry_message = tk.Entry(root, width=50)
entry_message.pack()

# Image Input
label_image = tk.Label(root, text="Select an image:")
label_image.pack()
entry_image = tk.Entry(root, width=50)
entry_image.pack()
button_browse = tk.Button(root, text="Browse", command=browse_image)
button_browse.pack()

# Password Input
label_password = tk.Label(root, text="Enter the password:")
label_password.pack()
entry_password = tk.Entry(root, width=50, show="*")
entry_password.pack()

# Encrypt Button
button_encrypt = tk.Button(root, text="Encrypt & Save", command=encrypt_message)
button_encrypt.pack()

root.mainloop()


