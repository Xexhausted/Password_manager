#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <unistd.h>

#define PASSWORD_LENGTH 16
#define FILENAME "passwords.db"
#define MASTER_PASSWORD_HASH_FILE "master_password.hash"
#define KEY_SIZE 32 // AES-256 key size
#define BLOCK_SIZE 16

void generate_password(char *password, int length);
void hash_master_password(const char *password, unsigned char *hash);
int verify_master_password(const char *input_password, unsigned char *stored_hash);
int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext);
void save_to_file(const char *filename, unsigned char *data, int data_len);
void setup_master_password();
int check_master_password(unsigned char *key);
void add_password(const unsigned char *key);
void retrieve_password(const unsigned char *key);

int main() {
    unsigned char key[KEY_SIZE];
    int choice;

    if (access(MASTER_PASSWORD_HASH_FILE, F_OK) == -1) {
        printf("No master password found. Setting up a new master password.\n");
        setup_master_password();
    }

    if (!check_master_password(key)) {
        printf("Incorrect master password. Exiting.\n");
        return 1;
    }

    while (1) {
        printf("\nPassword Manager Menu:\n");
        printf("1. Add Password\n");
        printf("2. Retrieve Password\n");
        printf("3. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                add_password(key);
                break;
            case 2:
                retrieve_password(key);
                break;
            case 3:
                printf("Exiting Password Manager. Goodbye!\n");
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
    return 0;
}

void generate_password(char *password, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int charset_size = strlen(charset);
    srand(time(NULL));
    for (int i = 0; i < length; i++) {
        password[i] = charset[rand() % charset_size];
    }
    password[length] = '\0';
}

void hash_master_password(const char *password, unsigned char *hash) {
    SHA256((const unsigned char *)password, strlen(password), hash);
}

int verify_master_password(const char *input_password, unsigned char *stored_hash) {
    unsigned char input_hash[SHA256_DIGEST_LENGTH];
    hash_master_password(input_password, input_hash);
    return memcmp(input_hash, stored_hash, SHA256_DIGEST_LENGTH) == 0;
}

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    unsigned char iv[BLOCK_SIZE] = {0}; // Fixed IV for demonstration purposes
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    unsigned char iv[BLOCK_SIZE] = {0}; // Fixed IV for demonstration purposes
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void save_to_file(const char *filename, unsigned char *data, int data_len) {
    FILE *file = fopen(filename, "a"); // Open in append mode
    if (file) {
        fwrite(data, sizeof(unsigned char), data_len, file);
        fputc('\n', file); // Add a newline to separate entries
        fclose(file);
    } else {
        perror("Failed to open file");
    }
}

void setup_master_password() {
    char master_password[100];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    printf("Set a new master password: ");
    scanf("%99s", master_password);

    hash_master_password(master_password, hash);
    save_to_file(MASTER_PASSWORD_HASH_FILE, hash, SHA256_DIGEST_LENGTH);
    printf("Master password setup complete.\n");
}

int check_master_password(unsigned char *key) {
    char master_password[100];
    unsigned char stored_hash[SHA256_DIGEST_LENGTH];

    printf("Enter master password: ");
    scanf("%99s", master_password);

    FILE *file = fopen(MASTER_PASSWORD_HASH_FILE, "r");
    if (!file || fread(stored_hash, 1, SHA256_DIGEST_LENGTH, file) != SHA256_DIGEST_LENGTH) {
        printf("Failed to read master password hash.\n");
        if (file) fclose(file);
        return 0;
    }
    fclose(file);

    if (verify_master_password(master_password, stored_hash)) {
        hash_master_password(master_password, key);
        return 1;
    } else {
        printf("Incorrect master password.\n");
        return 0;
    }
}

void add_password(const unsigned char *key) {
    char website[100], username[100], password[PASSWORD_LENGTH + 1], plaintext[256];
    unsigned char encrypted_data[256];

    printf("Website: ");
    scanf("%99s", website);
    printf("Username: ");
    scanf("%99s", username);

    generate_password(password, PASSWORD_LENGTH);
    printf("Generated Password: %s\n", password);

    snprintf(plaintext, sizeof(plaintext), "%s|%s|%s", website, username, password);
    int encrypted_len = encrypt_data((unsigned char *)plaintext, strlen(plaintext), key, encrypted_data);
    save_to_file(FILENAME, encrypted_data, encrypted_len);

    printf("Password saved successfully.\n");
}
void retrieve_password(const unsigned char *key) {
    unsigned char encrypted_data[1024], decrypted_data[256];
    char website[100], username[100];

    printf("Website to retrieve: ");
    scanf("%99s", website);
    printf("Username to retrieve: ");
    scanf("%99s", username);

    FILE *file = fopen(FILENAME, "r");
    if (!file) {
        printf("No passwords found.\n");
        return;
    }

    int found = 0;
    while (fgets((char *)encrypted_data, sizeof(encrypted_data), file)) {
        size_t encrypted_len = strlen((char *)encrypted_data);
        if (encrypted_len > 0 && encrypted_data[encrypted_len - 1] == '\n') {
            encrypted_data[--encrypted_len] = '\0'; // Remove newline
        }

        int decrypted_len = decrypt_data(encrypted_data, encrypted_len, key, decrypted_data);
        decrypted_data[decrypted_len] = '\0';

        // Check if both the website and username match
        char *website_ptr = strtok((char *)decrypted_data, "|");
        char *username_ptr = strtok(NULL, "|");
        if (website_ptr && username_ptr && strcmp(website_ptr, website) == 0 && strcmp(username_ptr, username) == 0) {
            printf("Details: %s|%s|%s\n", website_ptr, username_ptr, strtok(NULL, "|"));
            found = 1;
        }
    }
    fclose(file);

    if (!found) {
        printf("No matching website and username found.\n");
    }
}

