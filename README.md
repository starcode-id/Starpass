# Password Generator and Encryptor

This Python script allows users to generate secure passwords and encrypt them using a customizable salt. The tool can generate random passwords or encrypt user-provided passwords, providing an easy way to enhance password security.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [License](#license)
- [Author](#author)
- [Acknowledgments](#acknowledgments)

## Features

- **Random Password Generation**: Generate secure random passwords with a specified length.
- **Password Encryption**: Encrypt passwords using a customizable salt for added security.
- **Environment Variable Support**: Load configuration from a `.env` file for easier management of sensitive data.
- **User-Friendly Interface**: Displays a visually appealing banner and outputs encrypted passwords.

## Requirements

This project requires Python 3.6 or higher. The following packages are used:

- `cryptography`: For password encryption.
- `python-dotenv`: To load environment variables from a `.env` file.
- `pyfiglet`: To create ASCII banners.
- `pyperclip`: To copy the generated password to the clipboard.

## Installation

Follow these steps to set up the project on your local machine:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/starcode-id/Starpass
   cd Starpass
   pip install -r requirements.txt
   python main.py -p <your_password>

