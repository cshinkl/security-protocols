#include "CRC.h"

void fill_table(uint32_t* table) {
    uint32_t polynomial = REVERSED;
    for(size_t i = 0; i < TABLESIZE; ++i) {
        uint32_t crc = i;
        for(uint8_t j = 0; j < 8; ++j) {
            if(crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
}

uint32_t calc_crc(FILE* fp, const uint32_t* table) {
    // table and fp already verified to be valid 
    uint32_t crc = 0xFFFFFFFF;
    uint8_t buffer[4096]; // read 4KB at a time
    size_t bytes_read;

    while((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        for(size_t i = 0; i < bytes_read; ++i) {
            crc = table[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
        }
    }

    return crc ^ 0xFFFFFFFF;
}

int main(int argc, char* argv[]) {

    if(argc != 2) {
        printf("example command line usage:\n./CRC <input file>");
        return EXIT_FAILURE;
    }

    FILE* infile = fopen(argv[1], "rb");
    if(!infile) {
        perror("error opening specified file!\n");
        return EXIT_FAILURE;
    }

    uint32_t* table = (uint32_t*)(malloc(TABLESIZE * sizeof(uint32_t)));
    if(table == NULL) {
        perror("could not allocate table!\n");
        return EXIT_FAILURE;
    }

    // proper 256-entry table allocated, no need to verify in helper function
    fill_table(table);

    uint32_t crc = calc_crc(infile, table);
    fclose(infile);

    FILE* outfile = fopen("CRC-32.txt", "wb");
    if(!outfile) {
        perror("unable to open output file!\n");
        free(table);
        return EXIT_FAILURE;
    }
    fprintf(outfile, "%08X\n", crc);

    fclose(outfile);

    free(table);
    return EXIT_SUCCESS;
}