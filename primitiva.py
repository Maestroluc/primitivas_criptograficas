from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    with open('A.bin', 'wb') as file_out: # Guarda el mensaje cifrado en un archivo
        file_out.write(cipher.nonce)
        file_out.write(ciphertext)
    with open('key_AES.bin', 'wb') as key_out: # Guarda la clave en un archivo para su uso posterior en aes_decrypt()
        key_out.write(key)

def aes_decrypt():
    with open('key_AES.bin', 'rb') as key_in: 
        key = key_in.read() # Lee la clave del archivo
    with open('A.bin', 'rb') as file_in: 
        nonce = file_in.read(8)
        ciphertext = file_in.read() # Lee el mensaje cifrado del archivo
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print("El mensaje descifrado es: ", plaintext.decode('utf-8'))

def rsa_sign(message):
    key = RSA.generate(2048) # Genera un par de claves RSA de 2048 bits
    h = SHA256.new(message) # Calcula el hash del mensaje con SHA256

    with open('private_key.pem', 'wb') as f:
        f.write(key.export_key()) # Guarda la clave privada en un archivo para su uso posterior en rsa_verify()
    with open('public_key.pem', 'wb') as f: 
        f.write(key.publickey().export_key()) # Guarda la clave pública en un archivo para su uso posterior

    signature = pkcs1_15.new(key).sign(h)
    with open('signature.bin', 'wb') as f: # Guarda la firma en un archivo para su uso posterior en rsa_verify()
        f.write(signature)

def hmac_sha256(message):
    key = get_random_bytes(16) # Genera una clave aleatoria de 16 bytes (128 bits)
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    with open('C.bin', 'wb') as file_out:
        file_out.write(h.digest()) # Guarda el valor del hash en un archivo para su uso posterior
    print("Intentando crear el archivo key_hmac.bin...")  
    with open('key_hmac.bin', 'wb') as key_out:
        key_out.write(key) # Guarda la clave en un archivo para su uso posterior
    print("Archivo key_hmac.bin creado con éxito.")

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
        print("La firma es válida.")
    except (ValueError, TypeError):
        print("La firma no es válida.")

def hmac_verify():
    with open('key_hmac.bin', 'rb') as key_in: 
        key = key_in.read() # Lee la clave del archivo para su uso posterior
    with open('message.bin', 'rb') as message_in: 
        message = message_in.read()  # Lee el mensaje del archivo para su uso posterior
    with open('C.bin', 'rb') as file_in:
        hash = file_in.read() # Lee el valor del hash del archivo para su uso posterior
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    try:
        h.verify(hash) # Comprueba si el valor del hash es correcto
        print("El mensaje es auténtico")
    except ValueError:
        print("El mensaje o la clave son incorrectos")


def main():
    while True:
        print("\n1. Cifrar una cadena de texto usando AES")
        print("2. Descifrar un archivo binario usando AES")
        print("3. Firmar una cadena de texto usando RSA")
        print("4. Realizar una operación HMAC sobre una cadena de texto usando SHA256")
        print("5. Comprobar que la firma digital se ha hecho correctamente")
        print("6. Comprobar que el valor del HASH es correcto")
        print("7. Salir")
        option = input("\nSeleccione una opción: ")

        if option == '1':
            message = input("Introduzca el mensaje a cifrar: ").encode('utf-8')
            key = get_random_bytes(16)
            aes_encrypt(message, key) # Cifra el mensaje con AES
        elif option == '2':
            aes_decrypt()
        elif option == '3':
            message = input("Introduzca el mensaje a firmar: ").encode('utf-8')
            rsa_sign(message) # Firma el mensaje con RSA
        elif option == '4':
            message = input("Introduzca el mensaje a firmar: ").encode('utf-8')
            with open('message.bin', 'wb') as message_out:  # Guarda el mensaje en un archivo
                message_out.write(message)
            hmac_sha256(message) #
        elif option == '5':
            rsa_verify() # Comprueba si la firma es válida
        elif option == '6':
            hmac_verify() # Comprueba si el valor del hash es correcto
        elif option == '7':
            break

if __name__ == "__main__":
    main()