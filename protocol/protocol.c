#include <time.h>
#include <stdio.h>
#include <memory.h>
#include "../common/utils.h"
#include "protocol.h"


static const unsigned char SHARED_SECRET[30] = {
        0x2A, 0x2F, 0xED, 0x5E, 0x49, 0x26, 0x40, 0x19, 0x40, 0x40,
        0xE2, 0x51,	0xAA, 0xFA,	0xDB, 0xCB,	0x67, 0x21,	0x4C, 0xA4,
        0x10, 0x7E,	0x51, 0x22,	0x25, 0x11,	0x2B, 0x3C,	0x46, 0x5E
};

// Encoding / Decoding Logic for Legacy Packets



//Encrypt-Decrypt Response packets.
void CryptLegacyRequest(unsigned char* data, MDGRequest * out){
    MDLegacyRequest *request = (MDLegacyRequest *)data;

    unsigned int tmp_mask = (request->mask_key + GOLD_SALT) & 0xFFFFFFFF;
    unsigned char tmb_mask[4] = {0x00};
    memcpy(tmb_mask,&tmp_mask,4);

    request->dog_addr ^= (tmp_mask & 0xFFFF);
    request->dog_bytes ^= (tmp_mask & 0xFFFF);
    request->dog_password ^= tmp_mask;
    request->b_hostid ^= (tmp_mask & 0xFF);
    for(int i = 0 ; i < sizeof(request->dog_data); i++){
        request->dog_data[i] ^=  tmb_mask[i % 4];
    }

    // Copy to Our Intermediate Handler.
    out->magic = request->magic;
    out->operation_code = request->operation_code;
    out->dog_serial = request->dog_serial;
    out->mask_key_1 = request->mask_key;
    out->dog_addr = request->dog_addr;
    out->dog_bytes = request->dog_bytes;
    memcpy(out->dog_data,request->dog_data,sizeof(request->dog_data));
    out->dog_password = request->dog_password;
    out->b_hostid = request->b_hostid;
}

void CryptLegacyResponse(MDGResponse *in, unsigned char* data){
    unsigned char resp_data[sizeof(MDLegacyResponse)] = {0x00};
    MDLegacyResponse * response = (MDLegacyResponse *)resp_data;
    memcpy(response->dog_data,in->dog_data,sizeof(response->dog_data));
    response->dog_serial = in->dog_serial;
    response->status_code = in->status_code;

    unsigned int tmp_mask = (in->mask_key_1 + GOLD_SALT) & 0xFFFFFFFF;
    unsigned char tmb_mask[4] = {0x00};
    memcpy(tmb_mask,&tmp_mask,4);
    int i;
    for(i = 0 ; i < sizeof(response->dog_data); i++){
        response->dog_data[i] ^=  tmb_mask[i % 4];
    }

    memcpy(data-sizeof(MDLegacyResponse),resp_data,sizeof(MDLegacyResponse));
}



void GetAESMonthKey(unsigned char* key, unsigned char* ts_data){
    unsigned char month_secret[30] = {0x00};
    memcpy(month_secret,SHARED_SECRET,25);
    memcpy(month_secret+25,ts_data,2); // year
    memset(month_secret+27,45,1);
    memcpy(month_secret+28,ts_data+2,2); // month
    md5_hash(key,month_secret, sizeof(month_secret));
}



void EncryptRequest(MDGRequest * in, unsigned char* out){
    unsigned char* out_offset = out;
    MDRequest* req = (MDRequest*)out_offset; // Offset the packet header.
    req->magic = in->magic;
    req->operation_code = in->operation_code;
    req->mask_key_1 = in->mask_key_1;
    req->dog_cascade = in->dog_cascade;
    req->dog_serial = in->dog_serial;
    req->mask_key_2 = in->mask_key_2;
    req->dog_addr = in->dog_addr;
    req->dog_bytes = in->dog_bytes;
    req->mask_key_3 = in->mask_key_3;
    memcpy(req->dog_data,in->dog_data,sizeof(req->dog_data));
    req->dog_password = in->dog_password;
    req->b_hostid = in->b_hostid;
    req->mask_key_4 = in->mask_key_4;
    memcpy(&req->ts,&in->ts,sizeof(struct TimeStamp));



    req->magic ^= req->mask_key_1;
    req->operation_code ^= req->mask_key_1;

    req->magic ^= req->mask_key_2;
    req->operation_code ^= req->mask_key_2;
    req->mask_key_1 ^= req->mask_key_2;
    req->dog_cascade ^= req->mask_key_2;
    req->dog_serial ^= req->mask_key_2;

    req->magic ^= req->mask_key_3;
    req->operation_code ^= req->mask_key_3;
    req->mask_key_1 ^= req->mask_key_3;
    req->dog_cascade ^= req->mask_key_3;
    req->dog_serial ^= req->mask_key_3;
    req->mask_key_2 ^= req->mask_key_3;
    req->dog_addr ^= req->mask_key_3;
    req->dog_bytes ^= req->mask_key_3;


    req->magic ^= req->mask_key_4;
    req->operation_code ^= req->mask_key_4;
    req->mask_key_1 ^= req->mask_key_4;
    req->dog_cascade ^= req->mask_key_4;
    req->dog_serial ^= req->mask_key_4;
    req->mask_key_2 ^= req->mask_key_4;
    req->dog_addr ^= req->mask_key_4;
    req->dog_bytes ^= req->mask_key_4;
    req->mask_key_3 ^= req->mask_key_4;
    req->dog_password ^= req->mask_key_4;
    req->b_hostid ^= req->mask_key_4;

    for (int i = 0 ; i < sizeof(req->dog_data)/4 ; i++) {
        ((uint32_t *) req->dog_data)[i] ^= req->mask_key_4;
    }


    // Step 2 - Use Session Key to Encrypt Body
    aes_ecb_encrypt(out_offset,out_offset,in->session_key,MD40_REQHEAD_SIZE);

    // Step 3 - Use Base KEK to Encrypt... well... sessionKey
    uint8_t kek[16];
    md5_hash(kek,(unsigned char*)SHARED_SECRET, sizeof(SHARED_SECRET));
    aes_ecb_encrypt(out_offset+MD40_REQHEAD_SIZE,out_offset+MD40_REQHEAD_SIZE,kek,MD40_REQTAIL_SIZE);
}


void GetTimeFromDriverInAndDecryptLast16Bytes(unsigned char* in){
    unsigned char key[16]={0x00};
    md5_hash(key,(unsigned char*)SHARED_SECRET, sizeof(SHARED_SECRET));
    aes_ecb_decrypt(in,in,key,MD40_REQTAIL_SIZE);
}

void DecryptRequest(unsigned char* in,MDGRequest * out){
    // We have to make a copy of the input to somewhat cleanly do this.
    unsigned char tmp_in[sizeof(MDRequest)] = {0x00};
    memcpy(tmp_in,in+4,sizeof(MDRequest)); // Offset the packet header.

    GetTimeFromDriverInAndDecryptLast16Bytes(tmp_in+MD40_REQHEAD_SIZE);
    unsigned int ts_offset = MD40_REQHEAD_SIZE + 1;
    GetAESMonthKey(out->session_key, tmp_in+ts_offset);
    aes_ecb_decrypt(tmp_in,tmp_in,out->session_key,MD40_REQHEAD_SIZE);
    MDRequest* req = (MDRequest*)tmp_in;
    // Do the Mask Dance!
    req->magic ^= req->mask_key_4;
    req->operation_code ^= req->mask_key_4;
    req->mask_key_1 ^= req->mask_key_4;
    req->dog_cascade ^= req->mask_key_4;
    req->dog_serial ^= req->mask_key_4;
    req->mask_key_2 ^= req->mask_key_4;
    req->dog_addr ^= req->mask_key_4;
    req->dog_bytes ^= req->mask_key_4;
    req->mask_key_3 ^= req->mask_key_4;
    req->dog_password ^= req->mask_key_4;
    req->b_hostid ^= req->mask_key_4;

    for (int i = 0 ; i < sizeof(req->dog_data)/4 ; i++) {
        ((uint32_t *) req->dog_data)[i] ^= req->mask_key_4;
    }

    req->magic ^= req->mask_key_3;
    req->operation_code ^= req->mask_key_3;
    req->mask_key_1 ^= req->mask_key_3;
    req->dog_cascade ^= req->mask_key_3;
    req->dog_serial ^= req->mask_key_3;
    req->mask_key_2 ^= req->mask_key_3;
    req->dog_addr ^= req->mask_key_3;
    req->dog_bytes ^= req->mask_key_3;

    req->magic ^= req->mask_key_2;
    req->operation_code ^= req->mask_key_2;
    req->mask_key_1 ^= req->mask_key_2;
    req->dog_cascade ^= req->mask_key_2;
    req->dog_serial ^= req->mask_key_2;

    req->magic ^= req->mask_key_1;
    req->operation_code ^= req->mask_key_1;

    // Copy all Relevant Stuff to our Intermediate
    out->magic = req->magic;
    out->operation_code = req->operation_code;
    out->mask_key_1 = req->mask_key_1;
    out->dog_cascade = req->dog_cascade;
    out->dog_serial = req->dog_serial;
    out->mask_key_2 = req->mask_key_2;
    out->dog_addr = req->dog_addr;
    out->dog_bytes = req->dog_bytes;
    out->mask_key_3 = req->mask_key_3;
    unsigned int amt_to_copy = sizeof(out->dog_data);

    memcpy(out->dog_data,req->dog_data,amt_to_copy);
    out->dog_password = req->dog_password;
    out->b_hostid = req->b_hostid;
    out->mask_key_4 = req->mask_key_4;
    memcpy(&out->ts,&req->ts,sizeof(struct TimeStamp));

}


void EncryptResponse(unsigned char* session_key, MDGResponse* in, unsigned char* out){
    unsigned char tmp_res[sizeof(MDResponse)] = {0x00};
    size_t res_offset = sizeof(MDRequest)+4;

    memcpy(tmp_res,out+res_offset,sizeof(tmp_res));

    MDResponse* res = (MDResponse*)tmp_res;

    res->magic = in->magic;
    res->mask_key_1 = in->mask_key_1;
    res->operation_code = in->operation_code;
    res->mask_key_2 = in->mask_key_2;
    res->status_code = in->status_code;
    res->mask_key_3 = in->mask_key_3;

    memcpy(res->dog_data,in->dog_data,sizeof(in->dog_data));
    res->mask_key_4 = in->mask_key_4;


    for (int i = 0 ; i < sizeof(res->dog_data)/4 ; i++) {
        ((uint32_t *) res->dog_data)[i] ^= res->mask_key_4;
    }
    res->magic ^= res->mask_key_1;

    res->operation_code ^= res->mask_key_2;
    res->mask_key_1 ^= res->mask_key_2;
    res->magic ^= res->mask_key_2;

    res->status_code ^= res->mask_key_3;
    res->mask_key_2 ^= res->mask_key_3;
    res->operation_code ^= res->mask_key_3;
    res->mask_key_1 ^= res->mask_key_3;
    res->magic ^= res->mask_key_3;


    res->mask_key_3 ^= res->mask_key_4;
    res->status_code ^= res->mask_key_4;
    res->mask_key_2 ^= res->mask_key_4;
    res->operation_code ^= res->mask_key_4;
    res->mask_key_1 ^= res->mask_key_4;
    res->magic ^= res->mask_key_4;


    aes_ecb_encrypt(tmp_res,tmp_res,session_key,sizeof(MDResponse));
    memcpy(out+res_offset,tmp_res,sizeof(tmp_res));
}

void DecryptResponse(unsigned char* in, unsigned char* session_key, MDGResponse* out){
    // We have to make a copy of the input to somewhat cleanly do this.
    unsigned char tmp_in[sizeof(MDResponse)] = {0x00};
    memcpy(tmp_in,in,sizeof(MDResponse));
    aes_ecb_decrypt(tmp_in,tmp_in,session_key,sizeof(MDResponse));

    MDResponse* res = (MDResponse*)tmp_in;

    for (int i = 0 ; i < sizeof(res->dog_data)/4 ; i++) {
        ((uint32_t *) res->dog_data)[i] ^= res->mask_key_4;
    }

    res->mask_key_3 ^= res->mask_key_4;
    res->status_code ^= res->mask_key_4;
    res->mask_key_2 ^= res->mask_key_4;
    res->operation_code ^= res->mask_key_4;
    res->mask_key_1 ^= res->mask_key_4;
    res->magic ^= res->mask_key_4;

    res->status_code ^= res->mask_key_3;
    res->mask_key_2 ^= res->mask_key_3;
    res->operation_code ^= res->mask_key_3;
    res->mask_key_1 ^= res->mask_key_3;
    res->magic ^= res->mask_key_3;

    res->operation_code ^= res->mask_key_2;
    res->mask_key_1 ^= res->mask_key_2;
    res->magic ^= res->mask_key_2;

    res->magic ^= res->mask_key_1;


    // Copy to Generic Intermediate
    out->magic = res->magic;
    out->mask_key_1 = res->mask_key_1;
    out->operation_code = res->operation_code;
    out->mask_key_2 = res->mask_key_2;
    out->status_code = res->status_code;
    out->mask_key_3 = res->mask_key_3;

    memcpy(out->dog_data,res->dog_data,sizeof(res->dog_data));
    out->mask_key_4 = res->mask_key_4;

    for (int i = 0 ; i < 64 ; i++) {
        ((uint32_t *) out->dog_data)[i] ^= res->mask_key_4;
    }
}

void SetTimestamp(struct TimeStamp *ts){
    memset(ts,0x00,sizeof(struct TimeStamp));
    time_t now;
    struct tm *cal;

    now = time(NULL);
    cal = gmtime(&now);

    ts->year = cal->tm_year + 1900;
    ts->month = cal->tm_mon + 1;
    ts->day = cal->tm_mday;
    ts->hour = cal->tm_hour;
    ts->minute = cal->tm_min;
    ts->second = cal->tm_sec;
}

void PrintRequestInfo(MDGRequest* req){
    DEBUG_PRINT("[MDGRequest]\n");
    DEBUG_PRINT("Session Key: %s\n",hex_to_str(req->session_key,sizeof(req->session_key)));
    DEBUG_PRINT("Magic: %04X\n OpCode: %04X\n Mask1: %04X\n Mask2: %04X\n Mask3: %04X\n Mask4: %04X\n DogPass: %04X\n DogBytes: %04X\n DogAddr: %04X\n DogSerial: %04X\n DogCascade: %04X\n bHostId:%04X\n DogData: \n",
           req->magic,
           req->operation_code,
           req->mask_key_1,
           req->mask_key_2,
           req->mask_key_3,
           req->mask_key_4,
           req->dog_password,
           req->dog_bytes,
           req->dog_addr,
           req->dog_serial,
           req->dog_cascade,
           req->b_hostid
    );
    print_hex(req->dog_data,sizeof(req->dog_data));
}

void PrintResponseInfo(MDGResponse* res){
    DEBUG_PRINT("[MDGResponse]\n");
    DEBUG_PRINT("Magic: %04X\n OperationCode: %04X\n StatusCode: %04X\n Mask1: %04X\n Mask2: %04X\n Mask3: %04X\n Mask4: %04X\n DogSerial: %04X\n DogData: \n",
           res->magic,
           res->operation_code,
           res->status_code,
           res->mask_key_1,
           res->mask_key_2,
           res->mask_key_3,
           res->mask_key_4,
           res->dog_serial
    );

    print_hex(res->dog_data,sizeof(res->dog_data));
}

void GenerateAesMonthKey(unsigned char* key){
    struct TimeStamp ts;
    SetTimestamp(&ts);
    GetAESMonthKey(key, (unsigned char*)&ts);
}

void EncryptWithAesMonthKey(unsigned char* data, unsigned int length){
    unsigned char key[16] = {0x00};
    GenerateAesMonthKey(key);
    aes_ecb_encrypt(data,data,key,length);
}

void DecryptWithAesMonthKey(unsigned char* data, unsigned int length){
    unsigned char key[16] = {0x00};
    GenerateAesMonthKey(key);
    aes_ecb_decrypt(data,data,key,length);
}
