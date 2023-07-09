import os
import pickle
import random
import string

import pyperclip
from cryptography.fernet import Fernet, InvalidToken

PASSWORD_DB_NAME = os.path.join(os.path.dirname(__file__),"passwords.pkl")

def main(args):
    """Main function for password-manager."""
    choice = args.function
    if os.path.isfile(PASSWORD_DB_NAME):
        try:
            fernet = Fernet(args.secret)
            match choice: 
                case "get":
                    try:
                        getPassword(args.program, fernet)
                    except IndexError:
                        print("Invalid choice, usage: pm -f get -p <program name>. Try 'pm -f get -p test")
                case "add":
                    try:
                        addPassword(args.program, args.password, fernet)
                    except IndexError:
                        print("\n Invalid choice, usage: pm -f add -p <program name> <password>.")  
                case "generate":
                    if args.length:
                        password = generateRandomPassword(int(args.length))
                    else:
                        print("--length missing, generating a 12 digits password...")
                        password = generateRandomPassword(12)
                    print(f"Your secure generated password is:\n{password}")
                case _:
                    print("\n Invalid choice, usage: pm -f <add/get> -p <program name>.")
        except (ValueError, TypeError):
            match choice:
                case "setup":
                    generatePassFile()
                case _:
                    print("Error: Fernet key must be 32 url-safe base64-encoded bytes. Have you forgot to entered the correct secret?")
    else:
        match choice:
            case "setup":
                generatePassFile()          
            case _:
                print("\n Database not found, please run 'pm -f setup' to set it up.")  


def generateRandomPassword(length):
    """Generate and display a random password.
    
       Args: length (int), the length of the password to generate.

       Returns: password (string), the generated password.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for i in range(length))


def getPassword(element, fernet):
    """Attempt to retrive a password.
    
       Args: element(string), the element to retrieve.
             fernet(base64-encoded 32-byte key) the key used to decrypt.
    """
    with open(PASSWORD_DB_NAME, "rb") as passDict:
        try:
            while True:
                password=pickle.load(passDict)
                if element in password:
                    try:
                        decPassword = fernet.decrypt(password[f"{element}"]).decode()
                    except InvalidToken:
                        decPassword = generateRandomPassword(12)
                    pyperclip.copy(decPassword)
                    print("\nPassword copied.")
                    return
        except EOFError:
            print("Invalid choice, usage: pm -f get -p <program name>. Try 'pm get -f get -p test'")
            return


def addPassword(element, password, fernet):
    """Attempt to add a new program along with its' password.
    
       Args: element(string), the element to add.
             password(string), the password to pair with the element.
             fernet(base64-encoded 32-byte key) the key used to encrypt.
    """
    encPassword = fernet.encrypt(password.encode())
    with open(PASSWORD_DB_NAME, "rb+") as passDict:
        newPassDict = pickle.load(passDict)
        newPassDict[element] = encPassword
        pickle.dump(newPassDict,passDict)


def generatePassFile():
    """Generate a new password database along with a new encryption/decryption key."""
    key = Fernet.generate_key()
    secret = str(key).strip("b").strip("'")
    fernet = Fernet(key)
    print(f"This is your UNIQUE secret key, please do not share this with anyone and keep this somewhere safe as you will need it to retrieve your passwords.\n{secret}")
    encPassword = fernet.encrypt("test".encode())
    with open(PASSWORD_DB_NAME, "wb+") as passDict:
        pwd = {
        "test": bytes(encPassword),
        }
        pickle.dump(pwd, passDict)
        