import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt():
    message = message_entry.get().encode('utf-8')
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    with open('A.bin', 'wb') as file_out: # Guarda el mensaje cifrado en un archivo
        file_out.write(cipher.nonce)
        file_out.write(ciphertext)
    with open('key_AES.bin', 'wb') as key_out: # Guarda la clave en un archivo para su uso posterior
        key_out.write(key)
    messagebox.showinfo("Información", "Mensaje cifrado y guardado.")

def aes_decrypt():
    with open('key_AES.bin', 'rb') as key_in: 
        key = key_in.read() # Lee la clave del archivo
    with open('A.bin', 'rb') as file_in: 
        nonce = file_in.read(8)
        ciphertext = file_in.read() # Lee el mensaje cifrado del archivo
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    messagebox.showinfo("Información", "El mensaje descifrado es: " + plaintext.decode('utf-8'))

def rsa_sign():
    message = message_entry.get().encode('utf-8')
    key = RSA.generate(2048)
    h = SHA256.new(message)
    with open('private_key.pem', 'wb') as f:
        f.write(key.export_key())
    with open('public_key.pem', 'wb') as f:
        f.write(key.publickey().export_key())
    signature = pkcs1_15.new(key).sign(h)
    with open('signature.bin', 'wb') as f:
        f.write(signature)
    messagebox.showinfo("Información", "Mensaje firmado y guardado.")

def rsa_verify():
    with open('public_key.pem', 'rb') as f:
        key = RSA.import_key(f.read())
    with open('message.bin', 'rb') as f:
        message = f.read()
    with open('signature.bin', 'rb') as f:
        signature = f.read()
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        messagebox.showinfo("Información", "La firma es válida.")
    except (ValueError, TypeError):
        messagebox.showinfo("Información", "La firma no es válida.")

def hmac_sha256():
    global key
    message = message_entry.get().encode('utf-8')
    key = get_random_bytes(16)
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    with open('key_hmac.bin', 'wb') as f:
        f.write(h.digest())
    messagebox.showinfo("Información", "HMAC realizado y guardado.")

def hmac_verify():
    global key
    message = message_entry.get().encode('utf-8')
    with open('key_hmac.bin', 'rb') as f:
        hmac = f.read()
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    try:
        h.verify(hmac)
        messagebox.showinfo("Información", "El valor del hash es correcto.")
    except (ValueError, TypeError):
        messagebox.showinfo("Información", "El valor del hash no es correcto.")

root = tk.Tk()
root.title("Primitivas Criptográficas")

message_label = tk.Label(root, text="Mensaje:")
message_label.pack()

message_entry = tk.Entry(root)
message_entry.pack()

encrypt_button = tk.Button(root, text="Cifrar con AES", command=aes_encrypt)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Descifrar con AES", command=aes_decrypt)
decrypt_button.pack()

sign_button = tk.Button(root, text="Firmar con RSA", command=rsa_sign)
sign_button.pack()

verify_button = tk.Button(root, text="Verificar firma con RSA", command=rsa_verify)
verify_button.pack()

hmac_button = tk.Button(root, text="Realizar HMAC con SHA256", command=hmac_sha256)
hmac_button.pack()

hmac_verify_button = tk.Button(root, text="Verificar valor del hash HMAC", command=hmac_verify)
hmac_verify_button.pack()

root.mainloop()