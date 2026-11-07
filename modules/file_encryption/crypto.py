import os
from random import choice
from time import sleep

from pygments.styles.dracula import foreground

from core.validator import validate_file_path
from core.logger import setup_logger
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from colorama import Fore, Style, init

logger = setup_logger("PySecT-Config")

def decider():
    print(Fore.GREEN+ "[1] Encrypt file")
    print(Fore.GREEN+"[2] Decrypt file")
    choice=int(input("Please enter your choice:  "))
    if choice == 1:
        pass_phrase_creator()
    elif choice == 2:
        decrypt()
    else:
        print(Fore.RED+ "Invalid Choice")


def pass_phrase_creator():
    file_path= input("Enter the file path: ").strip()
    logger.info(f"User entered file path: {file_path}")
    validate_file_path(file_path)
    if validate_file_path(file_path):
        passphrase = input(Fore.YELLOW + "Enter the encryption passphrase: ").strip()

        if passphrase == "":
            print(Fore.RED + "Passphrase cannot be empty")
            logger.warning(f"Empty passphrase: {passphrase}")
        else:
            logger.info(f"User Entered Passphrase : {passphrase}")
            salting(passphrase, file_path)
    else:
        # print an error message if the filepath does not exits
        print(Fore.RED+f"file path: {file_path} does not exist")


def salting(passphrase, file_path):
    """
    Derive salt from passphrase
    """
    print(Fore.BLUE + "Generating salt...")

    salt = os.urandom(16)
    sleep(2)
    print(Fore.GREEN + "Generating key...")
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_100
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    print(Fore.YELLOW +f"Key generated successfully \n Attempting to encrypt file {file_path}")
    encryptor( key, salt, file_path)
    return key


def encryptor(   key,salt ,  file_path):
    file= file_path
    cipher = Fernet(key)
    with open(file, "rb") as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    file_dir = "docs"
    os.makedirs(file_dir, exist_ok=True)
    base_name = os.path.basename(file_path)
    output_file =f"{base_name}.enc"
    saved_file = os.path.join(file_dir, output_file)

    with open(saved_file, "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted_data)
    print(Fore.GREEN + f"Encryption success, file saved as {saved_file} in {file_dir} ")

def decrypt():
    file_path2 = input("Enter the file path: ").strip()
    logger.info(f"User entered file path: {file_path2}")
    validate_file_path(file_path2)
    if validate_file_path(file_path2):
        passphrase = input(Fore.YELLOW + "Enter the decryption passphrase: ").strip()

        if passphrase == "":
            print(Fore.RED + "Passphrase cannot be empty")
            logger.warning(f"Empty passphrase: {passphrase}")
        else:
            logger.info(f"User Entered Passphrase : {passphrase}")
            with open(file_path2, "rb") as file:
                file_data = file.read()
                salt2 = file_data[:16]
                encrypted_data = file_data[16:]
                print(Fore.GREEN + "Generating decrypting key...")
                sleep(2)
                kdf = PBKDF2HMAC(
                    algorithm=SHA256(),
                    length=32,
                    salt=salt2,
                    iterations=100_100
                )
                key2 = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
                cipher2 = Fernet(key2)

                print(Fore.GREEN + f"Key generated successfully \n Attempting to decrypt file {file_path2}")

                decrypted_data = cipher2.decrypt(encrypted_data)


                file_dir = "docs"
                os.makedirs(file_dir, exist_ok=True)
                original_filename = os.path.basename(file_path2).replace(".enc", "")
                restore_filename = f"restore_{original_filename}"
                saved_file = os.path.join(file_dir, restore_filename)
                with open(saved_file, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                print(Fore.GREEN+"File decrypted Successfully!!!!!!")
                print(Fore.BLUE + f"File {saved_file} saved in {file_dir}")





if __name__ == "__main__":
    pass_phrase_creator()





