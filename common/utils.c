#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
#include "md5.h"
#include "utils.h"


static int from_xdigit(char x){
    if (x >= '0' && x <= '9') {
        return x - '0';
    } else if (x >= 'a' && x <= 'f') {
        return 10 + x - 'a';
    } else if (x >= 'A' && x <= 'F') {
        return 10 + x - 'A';
    } else {
        return -1;
    }
}

static char to_xdigit(unsigned char val){
    if (val < 10) {
        return '0' + val;
    } else {
        return 'a' + (val - 10);
    }
}
char *hex_to_str(const unsigned char *bytes, unsigned int nbytes){
    char *str;
    int i;

    str = malloc(2 * nbytes + 1);
    for (i = 0 ; i < nbytes ; i++) {
        str[2 * i + 0] = to_xdigit(bytes[i]   >> 4);
        str[2 * i + 1] = to_xdigit(bytes[i] & 0x0F);
    }

    str[2 * nbytes] = '\0';

    return str;
}

void print_hex(unsigned char* data, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        DEBUG_PRINT("%02X", data[i]);
    }
    DEBUG_PRINT("\n");
}

int str_to_hex(unsigned char *bytes, unsigned int nbytes, const char *str){
    int hi_nibble;
    int lo_nibble;
    int i;

    for (i = 0 ; i < nbytes ; i++) {
        hi_nibble = from_xdigit(str[2 * i + 0]);
        if (hi_nibble < 0) return 0;

        lo_nibble = from_xdigit(str[2 * i + 1]);
        if (lo_nibble < 0) return 0;

        bytes[i] = (hi_nibble << 4) | lo_nibble;
    }

    return 1;
}

// Crypto Functions
unsigned char *get_random(unsigned int num_bytes){
    unsigned char *stream = malloc (num_bytes);
    size_t i;

    for (i = 0; i < num_bytes; i++){
        stream[i] = rand();
    }
    return stream;
}

void aes_ecb_encrypt(unsigned char* in, unsigned char* out, unsigned char* key, unsigned length){
    for(int i=0;i<length;i+=16){
        AES_ECB_encrypt(in+i,key,out+i,16);
    }
}
void aes_ecb_decrypt(unsigned char* in, unsigned char* out, unsigned char* key, unsigned length){
    for(int i=0;i<length;i+=16){
        AES_ECB_decrypt(in+i,key,out+i,16);
    }
}

void md5_hash(unsigned char* digest, unsigned char* in, unsigned int length){
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx,in, length);
    MD5Final(digest, &ctx);
}