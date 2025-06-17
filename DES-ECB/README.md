Implementation of DES encryption/decryption in ECB mode with PKCS#5 padding logic.

command line usage: ./DES-ECB [encrypt/decrypt] [input_filepath] [key_filepath]

Example:
gcc -o DES-ECB DES-ECB.c
./DES-ECB encrypt input.txt key.txt
./DES-ECB decrypt encrypted.txt key.txt

might come back to this at some point to implement threading since there is no inter-block dependencies

decryption currently takes twice as long as encryption which is funky
    - its probably just the outbuf logic though
    - also just some caching/branch prediction stuff happening so not much to be done there

currently competitive with a CPU runtime on Colab
