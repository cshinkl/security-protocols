#ifndef __CRC_H__
#define __CRC_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>

#define TABLESIZE 256
#define POLYNOMIAL 0x04C11DB7
#define REVERSED   0xEDB88320

void fill_table(uint32_t* table);
uint32_t calc_crc(FILE* fp, const uint32_t* table);

#endif /* __CRC_H__ */