command line usage: ./DES [encrypt/decrypt] [input_filepath] [key_filepath]

encryption/decryption working properly, haven't handled pad stripping yet 

improvements: could expand with PKCS #5/7 padding
-- padding bytes: hex value is the number of padding bytes
-- 0x DE AD BE EF 04 04 04 04
-- just gonna deal with extra binary data at end for now