// DES-CBC.c - performs DES encryption/decryption in CBC mode
#include "DES-CBC.h"

static const uint8_t IP[64] = {
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
};

static const uint8_t EXPANSION[48] = {
    31, 0, 1, 2, 3, 4,
    3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31, 0
};

static const uint8_t FP[64] = {
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
    32, 0, 40, 8, 48, 16, 56, 24
};

// S-boxes
static const uint8_t S_BOXES[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// P-box
static const uint8_t P_BOX[32] = {
    15, 6, 19, 20,
    28, 11, 27, 16,
    0, 14, 22, 25,
    4, 17, 30, 9,
    1, 7, 23, 13,
    31, 26, 2, 8,
    18, 12, 29, 5,
    21, 10, 3, 24
};

// round key shifts
static const uint8_t SHIFTS[NUMROUNDS] = {
    1, 1, 2, 2, 2, 2, 2, 2, 
    1, 2, 2, 2, 2, 2, 2, 1
};

// PC-1: 64-bit -> 56-bit key 
static const uint8_t PC1[56] = {
    56, 48, 40, 32, 24, 16, 8,
    0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26,
    18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
    6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3
};

// PC-2: 56-bit -> 48-bit round key
static const uint8_t PC2[48] = {
    13, 16, 10, 23, 0, 4,
    2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7,
    15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
};

// reads first 64 bits from keyfile to use as encryption key
bool read_key(const char* filepath, uint64_t* keybuffer) {
    FILE* fp = fopen(filepath, "r");
    if(fp == NULL) {
        perror("Unable to open key file!");
        return false;
    }

    if(fscanf(fp, "%" SCNx64, keybuffer) != 1) {
        perror("Failed to read 64-bit value from key file!");
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

uint64_t apply_pc1(uint64_t key) {
    uint64_t new_key = 0;

    for(uint8_t i = 0; i < POSTPC1SIZE; ++i) {
        uint64_t new_bit = (key >> (KEYSIZE - 1 - PC1[i])) & 1;
        new_key |= new_bit << (POSTPC1SIZE - 1 - i);
    }

    return new_key;
}

uint64_t apply_pc2(uint64_t key) {
    uint64_t new_key = 0;

    for(uint8_t i = 0; i < POSTPC2SIZE; ++i) {
        uint64_t new_bit = (key >> (POSTPC1SIZE - 1 - PC2[i])) & 1;
        new_key |= new_bit << (POSTPC2SIZE - 1 - i);
    }

    return new_key;
}

uint64_t apply_iperm(uint64_t chunk) {
    uint64_t result = 0;

    for (uint8_t i = 0; i < CHUNKSIZE; ++i) {
        uint64_t bit = (chunk >> (CHUNKSIZE - 1 - IP[i])) & 1;
        result |= bit << (CHUNKSIZE - i - 1);
    }
    return result;
}

uint64_t apply_fperm(uint64_t chunk) {
    uint64_t result = 0;

    for (uint8_t i = 0; i < CHUNKSIZE; ++i) {
        uint64_t bit = (chunk >> (CHUNKSIZE - 1 - FP[i])) & 1;
        result |= bit << (CHUNKSIZE - i - 1);
    }
    return result;
}

uint64_t apply_expansion(uint32_t block) {
    uint64_t result = 0;

    for(uint8_t i = 0; i < POSTPC2SIZE; ++i) {
        uint64_t bit = (block >> (BLOCKSIZE - 1 - EXPANSION[i])) & 1;
        result |= bit << (POSTPC2SIZE - i - 1);
    }
    return result;
}

uint32_t apply_sboxes(uint64_t expanded_block) {
    uint32_t result = 0;

    for (uint8_t i = 0; i < 8; ++i) {
        uint8_t chunk = (expanded_block >> (42 - 6*i)) & 0x3F;

        uint8_t row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        uint8_t col = (chunk >> 1) & 0x0F;

        uint8_t sbox_val = S_BOXES[i][row][col];

        result <<= 4;
        result |= sbox_val;
    }
    return result;
}

uint32_t apply_pbox(uint32_t block) {
    uint32_t result = 0;

    for (uint8_t i = 0; i < BLOCKSIZE; ++i) {
        uint32_t bit = (block >> (BLOCKSIZE - 1 - P_BOX[i])) & 1;
        result |= bit << (BLOCKSIZE - i - 1);
    }
    return result;
}

uint64_t circ_shift_left_28(uint64_t value, uint8_t shift_amount) {
    return ((value << shift_amount) | 
            ((value & 0xC000000) >> (28 - shift_amount))) & 0xFFFFFFF;
}

uint64_t generate_iv() {
    // less than ideal cryptographically
    // good enough for now
    return ((uint32_t)(rand() << 16)) | ((uint32_t)(rand() & 0xFFFF));
}

void get_round_keys(uint64_t key, uint64_t round_keys[NUMROUNDS], bool encrypt) {
    key = apply_pc1(key);
    uint64_t leftkey = (key >> 28) & 0xFFFFFFF; 
    uint64_t rightkey = (key & 0xFFFFFFF);

    for(uint8_t i = 0; i < NUMROUNDS; ++i) {
       leftkey = circ_shift_left_28(leftkey, SHIFTS[i]); 
       rightkey = circ_shift_left_28(rightkey, SHIFTS[i]); 
       uint64_t concat = (leftkey << 28) | rightkey;

       round_keys[encrypt ? i : (NUMROUNDS - i - 1)] = apply_pc2(concat);
    }
}

uint64_t make_uint64(uint8_t bytes[8], bool big_endian) {
    uint64_t value = 0;

    for(uint8_t i = 0; i < 8; ++i) {
        value <<= 8;
        value |= bytes[big_endian ? i : 7-i];
    }
    return value;
}

uint32_t fiestel(uint32_t rightblock, uint64_t roundkey) {
    uint64_t expanded = apply_expansion(rightblock);
    uint64_t xored = expanded ^ roundkey;
    uint64_t substituted = apply_sboxes(xored);
    return apply_pbox(substituted);
}

bool encrypt(const char* filepath, uint64_t key) {
    uint64_t iv = generate_iv();

    FILE* infile = fopen(filepath, "rb");
    if(infile == NULL) {
        perror("unable to open file for encryption!\n");
        return false;
    }

    FILE* outfile = fopen("encrypted.txt", "wb");
    if(outfile == NULL) {
        perror("unable to open file to store ciphertext!\n");
        return false;
    }
    
    // write IV as plaintext at start of outfile
    fwrite(&iv, sizeof(iv), 1, outfile);

    uint64_t round_keys[NUMROUNDS];
    get_round_keys(key, round_keys, true);

    size_t bytes_read;
    size_t chunks_encrypted = 0;
    uint8_t bytes[8];
    uint64_t ciphertext = 0;
    do {
        memset(bytes, 0, sizeof(bytes)); // automatic padding for encryption
        bytes_read = fread(bytes, 1, 8, infile);

        // PKCS#5 padding
        for(uint8_t i = bytes_read; i < 8; ++i) {
            bytes[i] = (uint8_t)(8 - bytes_read);
        }

        printf("padded chunk: ");
        for(int i = 0; i < 8; ++i) {
            printf("%02X ", bytes[i]);
        }
        printf("\n");
        uint64_t chunk = make_uint64(bytes, true);

        if(chunks_encrypted == 0) {
            chunk ^= iv;
        } else {
            chunk ^= ciphertext;
        }
        chunk = apply_iperm(chunk);

        uint32_t leftblock = (uint32_t)(chunk >> BLOCKSIZE);
        uint32_t rightblock = (uint32_t)(chunk & 0xFFFFFFFF);

        for(uint8_t round = 0; round < NUMROUNDS; ++round) {
            uint32_t tempblock = rightblock;
            rightblock = leftblock ^ fiestel(rightblock, round_keys[round]);
            leftblock = tempblock;
        }
        uint64_t preoutput = ((uint64_t)(rightblock) << BLOCKSIZE) | leftblock;
        ciphertext = apply_fperm(preoutput);

        fwrite(&ciphertext, sizeof(ciphertext), 1, outfile);
        ++chunks_encrypted;
    } while(bytes_read == 8);

    fclose(infile);
    fclose(outfile);

    return true;
}

bool decrypt(const char* filepath, uint64_t key) {
    // open file to decrypt
    FILE* infile = fopen(filepath, "rb");
    if(infile == NULL) {
        perror("unable to open file to decrypt!\n");
        return false;
    }

    FILE* outfile = fopen("decrypted.txt", "wb");
    if(outfile == NULL) {
        perror("unable to open file to store ciphertext!\n");
        return false;
    }
    
    // fetch IV from encrypted file
    uint64_t iv;
    size_t iv_read = fread(&iv, 8, 1, infile);
    if(iv_read < 1) {
        perror("issue fetching IV from encrypted file!");
        return false;
    }
    printf("IV: %016llX\n", (unsigned long long)iv);

    // generate round keys
    uint64_t round_keys[NUMROUNDS];
    get_round_keys(key, round_keys, false);

    uint8_t bytes[8];
    size_t bytes_read;
    size_t chunks_decrypted = 0;
    uint64_t xor_val;
    while ((bytes_read = fread(bytes, 1, 8, infile)) == 8) {

        uint64_t chunk = make_uint64(bytes, false);
        if(chunks_decrypted == 0) {
            xor_val = iv;
        } else {
            xor_val = chunk;
        }
        chunk = apply_iperm(chunk);

        uint32_t leftblock = (uint32_t)(chunk >> BLOCKSIZE);
        uint32_t rightblock = (uint32_t)(chunk & 0xFFFFFFFF);

        for (int round = 0; round < NUMROUNDS; ++round) {
            uint32_t temp = rightblock;
            rightblock = leftblock ^ fiestel(rightblock, round_keys[round]);
            leftblock = temp;
        }

        uint64_t preoutput = ((uint64_t)rightblock << BLOCKSIZE) | leftblock;
        uint64_t decrypted_block = apply_fperm(preoutput) ^ xor_val;

        uint8_t outbuf[8];
        for (int i = 0; i < 8; ++i) {
            outbuf[i] = (decrypted_block >> (8 * (7 - i))) & 0xFF;
        }

        uint8_t stop_idx = 8;
        if(outbuf[7] > 0 && outbuf[7] <= 8) {
            stop_idx -= outbuf[7];
        }

        fwrite(outbuf, 1, stop_idx, outfile);
        ++chunks_decrypted;
    }

    fclose(infile);
    fclose(outfile);

    return true;
}


int main(int argc, char* argv[]) {

    // for IV generation
    srand(time(NULL));

    if(argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt/decrypt> <input_filepath> <key_filepath>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint64_t key;
    if(!read_key(argv[3], &key)) {
        return EXIT_FAILURE;
    }

    if(strcmp(argv[1], "encrypt") == 0) {
        clock_t start = clock();
        if(!encrypt(argv[2], key)) {
            return EXIT_FAILURE;
        }
        clock_t end = clock();
        double ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;
        printf("encrypted successfully in %.3f ms!\n", ms);
    }
    else if(strcmp(argv[1], "decrypt") == 0) {
        clock_t start = clock();
        if(!decrypt(argv[2], key)) {
            return EXIT_FAILURE;
        }
        clock_t end = clock();
        double ms = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;
        printf("decrypted successfully in %.3f ms!\n", ms);
    } else {
        fprintf(stderr, "choose either encrypt or decrypt!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}