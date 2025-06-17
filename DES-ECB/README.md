Implementation of DES encryption/decryption in ECB mode with PKCS#5 padding logic.

command line usage: ./DES [encrypt/decrypt] [input_filepath] [key_filepath]

Example:
gcc -o DES DES.c
./DES encrypt input.txt key.txt
./DES decrypt encrypted.txt key.txt
