#include "CRC.h"

int main(int argc, char* argv[]) {

    uint32_t* table = (uint32_t*)(malloc(TABLESIZE * sizeof(uint32_t)));
    if(table == NULL) {
        perror("could not allocate table!\n");
        return EXIT_FAILURE;
    }

    free(table);
    return EXIT_SUCCESS;
}