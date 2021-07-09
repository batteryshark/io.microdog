#include <stdio.h>
#include <memory.h>
#include "../protocol/protocol.h"

#include "server_emulator.h"
#include "emulator_config.h"


void ProcessRequest(MDGRequest * req, MDGResponse * res, unsigned int print_info){
    if(print_info){
        DEBUG_PRINT("Server Request:\n");
        PrintRequestInfo(req);
    }
    res->operation_code = req->operation_code;
    res->dog_serial = req->dog_serial;
    res->magic = req->magic;
    res->mask_key_1 = req->mask_key_1;
    res->mask_key_2 = req->mask_key_2;
    res->mask_key_3 = req->mask_key_3;
    res->mask_key_4 = req->mask_key_4;
    res->status_code = 0;
    unsigned int resp_found = 0;
    switch(req->operation_code){
        case OP_UNK_0:
        case OP_WRITE_EX:
        case OP_HASH:
        case OP_SIGN:
        case OP_SET_SIGN_KEY:
        case OP_SET_CRYPT_KEY:
        case OP_GET_DEVICE_INFO:
        case OP_GET_TIME_LIMIT:
        case OP_SET_TIME_LIMIT:
        case OP_ACTIVATE_TIME_LIMIT:
            DEBUG_PRINT("[MicroDog] WARN: Unsupported Operation Code: %d\n",req->operation_code);
            break;
        case OP_CHECK: // Pretty sure this doesn't do anything.
            break;
        case OP_READ:
            if(req->dog_password != emu_dog.password) {
                res->status_code = ERR_PW;
                return;
            }
            memcpy(res->dog_data,emu_dog.memory+req->dog_addr,req->dog_bytes);
            break;
        case OP_WRITE:
            if(req->dog_password != emu_dog.password) {
                res->status_code = ERR_PW;
                return;
            }
            memcpy(emu_dog.memory+req->dog_addr,req->dog_data,req->dog_bytes);
            break;
        case OP_CONVERT:
        case OP_CONVERT_HASH:
            for(int i=0;i<emu_dog.num_convert_entries;i++){
                DOG_CONVERT_ENTRY* current_entry = emu_dog.convert_entry + i;
                if(!memcmp(req->dog_data,current_entry->request,req->dog_bytes)){
                    memcpy(res->dog_data,&current_entry->response,sizeof(current_entry->response));
                    resp_found = 1;
                    break;
                }
            }
            if(!resp_found){
                DEBUG_PRINT("[io.microdog] WARNING: RESPONSE NOT FOUND FOR REQUEST: %s\n",hex_to_str(req->dog_data,req->dog_bytes));
            }
            break;
        // UNDOCUMENTED: This one was from 4.09 / RC-UMH-LM-W32INTF, I've never seen it otherwise...
        case OP_GET_RANDOM:
            memcpy(res->dog_data,get_random(req->dog_bytes),req->dog_bytes);
            break;
        case OP_SET_PWD:
            if(req->dog_password != emu_dog.password) {
                res->status_code = ERR_PW;
                return;
            }
            emu_dog.password = *(uint32_t *)req->dog_data;
            break;
        case OP_SET_SHARE:
            emu_dog.share_flag = req->dog_data[0];
            res->dog_data[0] = emu_dog.share_flag;
            break;
        case OP_GET_MFG_SERIAL:
            *(uint32_t*)res->dog_data = emu_dog.mfg_serial;
            break;
        case OP_GET_ID:
            DEBUG_PRINT("Sending Dog ID: %s\n",hex_to_str(emu_dog.id,8));
            memcpy(res->dog_data,emu_dog.id,sizeof(emu_dog.id));
            break;
        case OP_SET_CASCADE:
            emu_dog.cascade = req->dog_data[0];
            res->dog_data[0] = emu_dog.cascade;
            break;
        case OP_DISABLE_SHARE:
            emu_dog.share_flag = 0;
            res->dog_data[0] = emu_dog.share_flag;
            break;
        case OP_ENABLE_SHARE:
            // In API 4.0, the global challenge data gets initialized.
            memset(emu_dog.g_ucChallengeData,0x00,sizeof(emu_dog.g_ucChallengeData));
            emu_dog.share_flag = 1;
            res->dog_data[0] = emu_dog.share_flag;
            break;
        case OP_VALIDATE_SERVER:
            aes_ecb_encrypt(req->dog_data,res->dog_data,req->session_key,16);
            break;
        case OP_VALIDATE_CLIENT:
            aes_ecb_decrypt(req->dog_data,req->dog_data,req->session_key,16);
            if(!memcmp(req->dog_data,emu_dog.g_ucChallengeData,16)){
                emu_dog.g_bPassAuthentication = 1;
                res->status_code = 0;
            }else{
                DEBUG_PRINT("ExternalAuthenticateApplication Mismatch: %s - Should be %s\n",hex_to_str(req->dog_data,16),hex_to_str(emu_dog.g_ucChallengeData,16));
                emu_dog.g_bPassAuthentication = 0;
                res->status_code = ERR_AUTH_CLIENT;
            }
            break;
        default:
            DEBUG_PRINT("[MicroDog] WARN: Invalid Operation Code: %d\n",req->operation_code);
            break;
    }
    if(print_info) {
        DEBUG_PRINT("Server Response:\n");
        PrintResponseInfo(res);
    }
}


// Helper to determine what kind of packet this is.
unsigned int DetectPacketVersion(unsigned char* packet_data){
    uint16_t packet_header = *(uint16_t*)packet_data;
    if(packet_header == PROTOCOL_VERSION_17) {
        return PROTOCOL_VERSION_17;
    }
    if(packet_header == PROTOCOL_VERSION_LEGACY) {
        return PROTOCOL_VERSION_LEGACY;
    }

    DEBUG_PRINT("New Packet Header Type: %04X\n",packet_header);
    return 0;
}

void HandlePacket(unsigned char* packet_data){
    MDGRequest req;
    memset(&req,0x00,sizeof(MDGRequest));
    MDGResponse res;
    memset(&req,0x00,sizeof(MDGResponse));
    // Figure out what Protocol we're using.
    unsigned int packet_version = DetectPacketVersion(packet_data);
    if(!packet_version){return;}

    // Decode our Packet
    switch(packet_version){
        case PROTOCOL_VERSION_LEGACY:
            CryptLegacyRequest(packet_data,&req);
            break;
        case PROTOCOL_VERSION_17:
            DecryptRequest(packet_data,&req);
            break;
        default:
            break;
    }

    // Actually process the request.
    ProcessRequest(&req,&res,1);

    // Re Encode our Packet and Store it where we need to.
    switch(packet_version){
        case PROTOCOL_VERSION_LEGACY:
            CryptLegacyResponse(&res,packet_data);
            break;
        case PROTOCOL_VERSION_17:
            EncryptResponse(req.session_key,&res,packet_data);
            // Set the packet header to 0.
            //memset(packet_data,0x00,4);
            *(uint32_t*)packet_data = 0;
            break;
        default:
            break;
    }
    DEBUG_PRINT("Sending Response...\n");
}

void InitEmulator(){
    DEBUG_PRINT("Starting io.microdog Emulator...\n");
    load_config();
}