#pragma once
//#define DEBUG
#ifdef DEBUG
#define DEBUG_PRINT(...) do{ printf(__VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) do{ } while ( 0 )
#endif

// Generic Stuff
#define PACKED __attribute__((packed))
char *hex_to_str(const unsigned char *bytes, unsigned int nbytes);
int str_to_hex(unsigned char *bytes, unsigned int nbytes, const char *str);
void print_hex(unsigned char* data, unsigned int len);
void aes_ecb_encrypt(unsigned char* in, unsigned char* out, unsigned char* key, unsigned length);
void aes_ecb_decrypt(unsigned char* in, unsigned char* out, unsigned char* key, unsigned length);
void md5_hash(unsigned char* digest, unsigned char* in, unsigned int length);
unsigned char *get_random(unsigned int num_bytes);


