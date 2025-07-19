#include "chacha20.h"

void z_data_copy(void)
{
	// imp data decryption here
    struct chacha20_context ctx;
    char key[32] = {};
    char nonce[12] = {};
    
    key[0]  = 0xe3;
    key[1]  = 0x82;
    key[2]  = 0x84;
    key[3]  = 0xe3;
    key[4]  = 0x82;
    key[5]  = 0x8a;
    key[6]  = 0xe3;
    key[7]  = 0x81;
    key[8]  = 0xbe;
    key[9]  = 0xe3;
    key[10] = 0x81;
    key[11] = 0x99;
    key[12] = 0xe3;
    key[13] = 0x81;
    key[14] = 0xad;
    key[15] = 0xe3;
    key[16] = 0x82;
    key[17] = 0x84;
    key[18] = 0xe3;
    key[19] = 0x82;
    key[20] = 0x8a;
    key[21] = 0xe3;
    key[22] = 0x81;
    key[23] = 0xbe;
    key[24] = 0xe3;
    key[25] = 0x81;
    key[26] = 0x99;
    key[27] = 0xe3;
    key[28] = 0x81;
    key[29] = 0xad;
    key[30] = 0x0;
    key[31] = 0x0;
    
    char *data_start = NULL;
    int size_of_buffer = 0x87;

    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, data_start, size_of_buffer);
}
