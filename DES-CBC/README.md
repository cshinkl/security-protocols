Implementation of DES encryption/decryption in CBC mode with PKCS#5 padding logic. Currently uses stdlib rand() for IV generation (not cryptographically secure, but easier for now)

Encrypted data (encrypted.txt) will be raw binary data, decrypted data (decrypted.txt) will be recovered plaintext (ASCII)

command line usage: ./DES-ECB [encrypt/decrypt] [input_filepath] [key_filepath]

Example:
gcc -o DES-CBC DES-CBC.c
./DES-CBC encrypt input.txt key.txt
./DES-CBC decrypt encrypted.txt key.txt

decryption is apparently parallelizable so i may come back to that

