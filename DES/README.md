TODO - do some testing for just encryption (treat input / output as hexstring)
    - verify against online calculator
    - round keys look good, need to double check s-boxes

command line usage: ./DES [encrypt/decrypt] [input_filepath] [key_filepath]

improvements: could expand with PKCS #5/7 padding
-- padding bytes: hex value is the number of padding bytes
-- 0x DE AD BE EF 04 04 04 04
-- just gonna deal with extra binary data at end for now