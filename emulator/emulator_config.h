#pragma once
#define PACKED __attribute__((packed))
typedef struct PACKED _CONVERT_ENTRY{
    unsigned char request[64];
    unsigned int request_len;
    unsigned int response;
}DOG_CONVERT_ENTRY;


typedef struct PACKED _EMULATED_DOG{
    unsigned int algorithm;
    unsigned char g_ucChallengeData[16];
    unsigned int g_bPassAuthentication;
    unsigned char cascade;
    unsigned char share_flag;
    unsigned int password;
    unsigned int serial;
    unsigned char id[8];
    unsigned int mfg_serial;
    unsigned char memory[200];
    unsigned int num_convert_entries;
    DOG_CONVERT_ENTRY* convert_entry;
}EMULATED_DOG;

extern EMULATED_DOG emu_dog;

void load_config();