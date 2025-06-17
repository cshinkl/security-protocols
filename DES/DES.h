#ifndef __DES_H__
#define __DES_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#define CHUNKSIZE 64
#define KEYSIZE 64
#define BLOCKSIZE 32
#define NUMROUNDS 16
#define POSTPC1SIZE 56
#define POSTPC2SIZE 48

bool read_key(const char* filepath, uint64_t* keybuffer);
bool encrypt(const char* filepath, uint64_t key);
bool decrypt(const char* filepath, uint64_t key);

uint64_t apply_pc1(uint64_t key);
uint64_t apply_pc2(uint64_t key);
uint64_t apply_iperm(uint64_t chunk);
uint64_t apply_fperm(uint64_t chunk);
uint64_t apply_expansion(uint32_t block);
uint32_t apply_sboxes(uint64_t expanded_block);
uint32_t apply_pbox(uint32_t block);

uint32_t fiestel(uint32_t rightblock, uint64_t roundkey);

uint64_t make_uint64(uint8_t bytes[8]);
uint64_t circ_shift_left_28(uint64_t value, uint8_t shift_amount);
void get_round_keys(uint64_t key, uint64_t round_keys[NUMROUNDS], bool encrypt);

#endif /* __DES_H__ */