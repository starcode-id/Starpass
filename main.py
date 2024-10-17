#!/usr/bin/env python3
import os
import secrets
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64
import argparse
import pyfiglet
import pyperclip 
from dotenv import load_dotenv
# change script dir sesuai directory anda
script_dir = '/opt/starpass/.env'
dotenv_path = os.path.join(script_dir)
load_dotenv(dotenv_path=dotenv_path)

def get_argument():
    default_salt = os.getenv('SALT')
    parser = argparse.ArgumentParser(description="Password Generator and Encrypt")
    parser.add_argument('-p', "--password", type=str, dest="password", help="password to be encrypted")
    parser.add_argument("-r", "--random",action="store_true", dest="random", help="generate a random password")
    parser.add_argument("-s", "--salt", type=str, dest="salt",default=default_salt ,help="custom salt for encrypted password")
    parser.add_argument("-l", "--length", type=int, dest="length", default=20, help="Length of the generated password")
    return parser.parse_args()

def generate_password(length):
    """
    Generate a random password with the given length.
    The password will contain at least one uppercase letter, one lowercase letter, one digit, and one special character.
    """
    if length < 4:
        raise ValueError("Password length should be at least 4 characters")

    # Define the character sets
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower_case = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
    # Ensure the password has at least one character from each character set
    password = [
        secrets.choice(upper_case),
        secrets.choice(lower_case),
        secrets.choice(digits),
        secrets.choice(special_characters)
    ]

    # Fill the rest of the password length with random choices from all character sets combined
    all_characters = upper_case + lower_case + digits + special_characters
    password += [secrets.choice(all_characters) for _ in range(length - 4)]

    # Shuffle the password list to ensure randomness
    secrets.SystemRandom().shuffle(password)

    # Convert the password list to a string and return it
    return ''.join(password)

def encrypt_password(password, custom_salt=None):
    if custom_salt:
        # If custom_salt is provided as a plain string, encode it to bytes
        salt = custom_salt.encode()
    else:
        # Generate a random salt if custom_salt is not provided
        salt = os.urandom(16)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    encrypted_password = base64.urlsafe_b64encode(key).decode()  # Encode key to base64 and decode to string
    return encrypted_password

def display_output(output, length=None):
    password = []
    for i in range(length - 2):
        password.append(output[i])
    if len(password) % 2 == 0:
        middle_index = len(password) // 2
    else:
        middle_index = len(password) // 2 + 1
    secret_char1 = os.getenv('SECRET1')
    secret_char2 = os.getenv('SECRET2')
    password = password[:middle_index] + [secret_char1] + password[middle_index:]
    password.insert(-3, "@")
    password_str = ''.join(password)
    if length and len(output) > length:
        
        masked_output = '*' * length
    else:
        masked_output = '*' * len(output)
    if length:
        print(f"Password encrypted: {masked_output}")
        pyperclip.copy(password_str)
    else:
        print(f"Password: {password_str}")
        pyperclip.copy(password_str)
def print_banner():
    banner = pyfiglet.figlet_format("Starpass", font="slant", justify="center")
    subBaner = pyfiglet.figlet_format("By: StarCode", font = "digital", justify='center')
    print(banner)
    print(subBaner)
def main():
    print_banner()
    options = get_argument()
    if options.random:
        password = generate_password(options.length)
        display_output(password, options.length)
    elif options.password:
        encrypted_password = encrypt_password(options.password, options.salt)
        display_output(encrypted_password, options.length)
    else:
        print("Please provide a password to encrypt or use --random to generate a random password. Use -h for help.")

if __name__ == "__main__":
    main()