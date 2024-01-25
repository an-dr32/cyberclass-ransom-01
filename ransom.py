import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256

"""
Este script en Python es una implementación de un programa simple para cifrar y descifrar archivos utilizando 
el cifrado AES (Estándar de Cifrado Avanzado) en el modo CBC (Cipher Block Chaining). 
Utiliza la biblioteca PyCryptodome para operaciones criptográficas.
"""

#Función de cifrado (encrypt)
def encrypt(key, filename):
    chunksize = 64*1024                                   # Define el tamaño del fragmento para leer y procesar el archivo.
    outputFile = filename+".enc"                          # Especifica el nombre del archivo cifrado.
    filesize = str(os.path.getsize(filename)).zfill(16)   # Obtiene el tamaño del archivo original y lo rellena con ceros hasta 16 dígitos.
    IV = Random.new().read(16)                            # Genera un Vector de Inicialización (IV) aleatorio de 16 bytes.
    encryptor = AES.new(key, AES.MODE_CBC, IV)            # Crea un objeto de cifrado AES con la clave y el IV proporcionados en modo CBC.

    # La función luego lee el archivo de entrada en fragmentos, rellena el último fragmento si es necesario y escribe los datos cifrados en el archivo de salida.
    with open(filename, "rb") as infile:
        with open(outputFile, "wb") as outfile:
            outfile.write(filesize.encode("utf-8"))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0:
                    chunk += b'.'*(16-(len(chunk)%16))

                    outfile.write(encryptor.encrypt(chunk))
                    
#Función de descifrado (decrypt)
    #Similar a la función de cifrado, pero lee el IV y el tamaño del archivo desde la cabecera del archivo cifrado.
def decrypt(key, filename):
    chunksize = 64*1024
    outputFile = filename[:-4]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)         # Crea un objeto de cifrado AES para descifrar utilizando la clave y el IV proporcionados.

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)
        #La función lee fragmentos del archivo cifrado, los descifra y escribe los datos descifrados en el archivo de salida. 
        #También trunca el archivo de salida al tamaño original del archivo.

# Función de derivación de clave (getKey):
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))          # Utiliza SHA-256 para hashear la contraseña y devuelve el resumen como clave.
    return hasher.digest()

#Función principal (Main):
def Main():
    #Pregunta al usuario si desea cifrar o descifrar (choice variable).
    choice = input("Te gustaria CIFRAR (C o descifrar (D))")

    #Para el cifrado, toma la ruta del archivo y la contraseña, deriva la clave y llama a la función encrypt
    if choice == 'C':
        filename = input("Ruta de archivo a cifrar: ")
        password = input("Contrasena para cifrado: ")
        encrypt(getKey(password), filename)
        print('HECHO!')
    #Para el descifrado, toma la ruta del archivo y la contraseña, deriva la clave y llama a la función decrypt.
    elif choice == 'D':
        filename = input("Ruta de archivo a descifrar: ")
        password = input("Contrasena para descifrado: ")
        decrypt(getKey(password), filename)
        print("HECHO!")

    else:
        print("Ninguna opcion ha sido seleccionada.")

    Main()

    """
    Ten en cuenta que el cifrado y descifrado son operaciones sensibles y este script es un ejemplo básico con fines educativos. 
    Carece de algunas características de seguridad importantes, como la gestión adecuada de claves, el manejo seguro de contraseñas y la autenticación. 
    Si estás considerando usar esto en algún escenario del mundo real, se necesitan medidas de seguridad adicionales y consideraciones.
    """