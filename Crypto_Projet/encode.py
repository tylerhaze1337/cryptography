from cryptography.fernet import Fernet
from colorama import Fore
import subprocess
import os 



def Encryption():

    # Generer une cle de chiffrement
    key = Fernet.generate_key()
    cipher = Fernet(key)

    #Fichier input 
    Fichier = input(f"{Fore.LIGHTGREEN_EX} the main file here : ")
    

  
    # Chiffrer le fichier
    with open(Fichier, 'rb') as f:
        original_data = f.read()
    encrypted_data = cipher.encrypt(original_data)

    # Sauvegarder le fichier chiffre
    with open(f'{Fichier}.enc', 'wb') as f:
        f.write(encrypted_data)
    print(f"{Fore.LIGHTGREEN_EX}Fichier chiffre avec succes !")

    while True:
        print("Start The execusion")
        input("")
        # Charger la cle de chiffrement/dechiffrement
        print(f"{key}")
        cipher = Fernet(key)

        # Dechiffrer le fichier
        with open (f'{Fichier}.enc')as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)

        # Sauvegarder temporairement le fichier dechiffre
        temp_file = f'{Fichier}_temp.ps1'
        with open(temp_file, 'wb') as f:
            f.write(decrypted_data)

        # Executer le fichier dechiffre
        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", temp_file])

        # Supprimer le fichier temporaire apres execution
        os.remove(temp_file)

        # Rechiffrer le fichier
        re_encrypted_data = cipher.encrypt(decrypted_data)
        with open(f'{Fichier}.ps1.enc', 'wb') as f:
            f.write(re_encrypted_data)
            print("Fichier rechiffre avec succes !")
            
        