# Password Manager

A simple password manager written in C, using OpenSSL for AES encryption. The program allows users to securely store and retrieve passwords associated with different websites and usernames. It leverages a master password for encryption and provides functionality for adding new passwords or retrieving existing ones.

## Features

- **AES-256 Encryption**: Passwords and related data are encrypted using AES-256-CBC for secure storage.
- **Master Password**: The program uses a master password to derive an AES key, which is used for encrypting and decrypting stored passwords.
- **Password Generation**: Generates random passwords of a specified length with a mix of letters, numbers, and special characters.
- **Storage**: Encrypted password data is stored in a file for later retrieval.
- **Password Retrieval**: Retrieve stored passwords by providing the website and username associated with them.
- **OpenSSL**: Uses OpenSSL's cryptographic libraries (EVP, AES, SHA256) for encryption and hashing.

## Requirements

- **OpenSSL**: Make sure OpenSSL is installed on your system for the cryptographic operations.
  - On Ubuntu/Debian-based systems, you can install it with:
    ```bash
    sudo apt-get install libssl-dev
    ```

- **C Compiler**: A C compiler (e.g., GCC) to compile the source code.

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

### 2. Compile the Code

```bash
gcc -o password_manager password_manager.c -lssl -lcrypto
```

### 3. Run the Program

```bash
./password_manager
```

## Usage

### Master Password Setup
- The first time you run the program, you will be prompted to set a master password. This password will be used to derive an encryption key for securing your stored passwords.

### Adding a Password
- Select the option to "Add Password" from the menu.
- You will be prompted to provide the website and username, and the program will generate a random password for you.

### Retrieving a Password
- Select the option to "Retrieve Password" from the menu.
- Enter the website and username for which you want to retrieve the password. The program will decrypt the stored data and display the credentials.

## Files

- `passwords.db`: Stores encrypted password data.
- `master_password.hash`: Contains the hashed version of the master password (for verification purposes).

## Security Considerations

- The program uses AES-256-CBC encryption with a fixed initialization vector (IV). In real-world applications, you should use a secure, random IV for each encryption operation.
- The master password is hashed using SHA-256 for secure comparison during login.
- All sensitive data (passwords, usernames) are stored encrypted to prevent unauthorized access.

Feel free to modify the content according to your preferences or project requirements.
