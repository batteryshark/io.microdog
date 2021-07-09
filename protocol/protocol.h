#pragma once
#include "../common/utils.h"

#include <stdint.h>

#define PROTOCOL_VERSION_17 0x11
#define PROTOCOL_VERSION_16 0x10
#define PROTOCOL_VERSION_LEGACY 0x484D
#define PACKET_MAGIC 0x484D


struct PACKED TimeStamp{
    uint16_t year;
    uint16_t month;
    uint16_t day;
    uint16_t hour;
    uint16_t minute;
    uint16_t second;
    uint8_t padding[3];
};



typedef struct PACKED MD_Generic_Request{
    uint8_t  session_key[16];
    uint16_t magic;
    uint32_t mask_key_1;
    uint32_t mask_key_2;
    uint32_t mask_key_3;
    uint32_t mask_key_4;
    uint16_t operation_code;
    uint8_t dog_cascade;
    uint32_t dog_serial;
    uint16_t dog_addr;
    uint16_t dog_bytes;
    uint8_t dog_data[256];
    uint32_t dog_password;
    uint8_t b_hostid;
    struct TimeStamp ts;
}MDGRequest;

typedef struct PACKED MD_Generic_Response{
    uint16_t magic;
    uint16_t operation_code;
    uint32_t dog_serial;
    uint32_t status_code;
    uint8_t dog_data[256];
    uint32_t mask_key_1;
    uint32_t mask_key_2;
    uint32_t mask_key_3;
    uint32_t mask_key_4;
}MDGResponse;


typedef struct PACKED MD_Legacy_Request{
    uint16_t magic;
    uint16_t operation_code;
    uint32_t dog_serial;
    uint32_t mask_key;
    uint16_t dog_addr;
    uint16_t dog_bytes;
    uint8_t  dog_data[256];
    uint32_t dog_password;
    uint8_t  b_hostid;
}MDLegacyRequest;

typedef struct PACKED MD_Legacy_Response{
    uint32_t dog_serial;
    uint32_t status_code;
    uint8_t dog_data[256];
    uint8_t padding[8];
}MDLegacyResponse;

typedef struct PACKED MD_Request{
    uint16_t magic;
    uint8_t operation_code;
    uint32_t mask_key_1;
    uint8_t dog_cascade;
    uint32_t dog_serial;
    uint32_t mask_key_2;
    uint16_t dog_addr;
    uint16_t dog_bytes;
    uint32_t mask_key_3;
    uint8_t dog_data[256];
    uint32_t dog_password;
    uint8_t b_hostid;
    uint32_t mask_key_4;
    struct TimeStamp ts;
} MDRequest;

typedef struct PACKED MD_Response{
    uint16_t magic;
    uint32_t mask_key_1;
    uint8_t operation_code;
    uint32_t mask_key_2;
    uint32_t status_code;
    uint32_t mask_key_3;
    uint8_t dog_data[256];
    uint32_t mask_key_4;
    uint8_t padding[9];
} MDResponse;

// Helpful Constants
#define MD40_REQHEAD_SIZE 0x120
#define MD40_REQTAIL_SIZE 0x10
#define GOLD_SALT 0x646C6F47

// Packet Encrypt/Decrypt Functions
void CryptLegacyResponse(MDGResponse *in, unsigned char* data);
void CryptLegacyRequest(unsigned char* data, MDGRequest* out);
void EncryptRequest(MDGRequest * in, unsigned char* out);
void DecryptRequest(unsigned char* in, MDGRequest * out);
void EncryptResponse(unsigned char* session_key, MDGResponse* in, unsigned char* out);
void DecryptResponse(unsigned char* in, unsigned char* session_key, MDGResponse* out);
void SetTimestamp(struct TimeStamp *ts);
void GenerateAesMonthKey(unsigned char* key);
void EncryptWithAesMonthKey(unsigned char* data, unsigned int length);
void DecryptWithAesMonthKey(unsigned char* data, unsigned int length);
void PrintRequestInfo(MDGRequest* req);
void PrintResponseInfo(MDGResponse* res);

// Operation Codes
#define OP_UNK_0                  0x00
#define OP_CHECK                  0x01
#define OP_READ                   0x02
#define OP_WRITE                  0x03
#define OP_CONVERT                0x04
#define OP_GET_RANDOM             0x05
#define OP_SET_PWD                0x07
#define OP_SET_SHARE              0x08
#define OP_GET_MFG_SERIAL         0x0B
#define OP_WRITE_EX               0x0E
#define OP_HASH                   0x11
#define OP_SIGN                   0x12
#define OP_GET_ID                 0x14
#define OP_SET_CASCADE            0x15
#define OP_SET_SIGN_KEY           0x19
#define OP_SET_CRYPT_KEY          0x1A
#define OP_GET_DEVICE_INFO        0x3F
#define OP_CONVERT_HASH           0x40
#define OP_DISABLE_SHARE          0x64
#define OP_ENABLE_SHARE           0x65
// Take 16 bytes of random, send it to the dongle,the dongle encrypts it with the session key and sends it back to the client
// which decrypts it with the month key and checks it against what it sent
#define OP_VALIDATE_SERVER        0x66
// Sends 16 bytes of null encrypted with the aesmonthkey to the server for validation
#define OP_VALIDATE_CLIENT        0x67
#define OP_GET_TIME_LIMIT         0xC8
#define OP_SET_TIME_LIMIT         0xC9
#define OP_ACTIVATE_TIME_LIMIT    0xCA

#define ERR_PW 0x2745
#define ERR_AUTH_CLIENT 20023
#define ERR_AUTH_SERVER 30009


