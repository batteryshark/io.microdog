#ifndef MH_EXTENSION
#define MH_EXTENSION
#include "gsmh.h"
#include <stdio.h>
#define MD_MAGIC         0x484D
#define MD_RTADD         0x539
#define MD_SETDOGSERIAL  0x53A
#define MD_SETPASSWORD   0x07
#define MD_SETMFGSERIAL  0x53B
#define MD_SETVID        0x53C
#define MD_RLRT          0x53D
#define MD_XACT          0x6B00
#define GOLD_SALT        0x646C6F47

//The library originally expected all packets to have the response above the request.
typedef struct RequestResponse{
	unsigned int   dog_serial_resp;
	unsigned int   return_code;
	unsigned char   dog_data_resp[256];
	unsigned short magic;
	unsigned short opcode;
	unsigned int   dog_serial;
	unsigned int   mask_key;
	unsigned short dog_addr;
	unsigned short dog_bytes;
	unsigned char  dog_data[256];
	unsigned int   dog_password;
	unsigned char  b_hostid;
}RequestResponse;

void crypt_request(RequestResponse *request){
    
	unsigned int tmp_mask = (request->mask_key + GOLD_SALT) & 0xFFFFFFFF;
    unsigned char tmb_mask[4] = {0x00};
    memcpy(tmb_mask,&tmp_mask,4);
   
    request->dog_addr ^= (tmp_mask & 0xFFFF);
    request->dog_bytes ^= (tmp_mask & 0xFFFF);
    request->dog_password ^= tmp_mask;
    request->b_hostid ^= (tmp_mask & 0xFF);
    int i;
    for(i = 0 ; i < 256; i++){
     request->dog_data[i] ^=  tmb_mask[i % 4]; 

    }
}

void gen_req(RequestResponse *req,unsigned short opcode){
	req->magic = MD_MAGIC;
	req->opcode = opcode;
	req->dog_serial = 0x00;
	req->dog_serial_resp = req->dog_serial;
	memset(&req->dog_data_resp,0x00,256);
	memset(&req->dog_data,0x00,256);
	req->return_code = 0;
	req->dog_password = 0;
	req->b_hostid = 0;
	req->mask_key = 0x00;
	req->dog_addr = 0;
}



unsigned long RTAdd(){
	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_RTADD);
	
	req.dog_bytes = DogBytes;
	memcpy(&req.dog_data,DogData,req.dog_bytes);
	req.dog_password = DogPassword;
	
	crypt_request(&req);
	errcode = LinuxUsbDriverEntry(&req.magic);
	return errcode;
}

unsigned long SetDogSerial(){
    
	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_SETDOGSERIAL);
	

	memcpy(&req.dog_data,DogData,4);
	
	
	crypt_request(&req);
	
	errcode = LinuxUsbDriverEntry(&req.magic);
	return errcode;
}

unsigned long SetPassword(){
	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_SETPASSWORD);
	memset(req.dog_data,NewPassword,4);
	
	
	req.dog_password = DogPassword;
	
	crypt_request(&req);
	
	errcode = LinuxUsbDriverEntry(&req.magic);
	
	return errcode;
}

unsigned long SetMfgSerial(){
	
	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_SETMFGSERIAL);
	
	memcpy(&req.dog_data,DogData,4);
	
	crypt_request(&req);
	
	errcode = LinuxUsbDriverEntry(&req.magic);
	
	return errcode;
}

unsigned long ReloadRainbowTable(){
  	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_SETMFGSERIAL);
	
	
	crypt_request(&req);
	
	errcode = LinuxUsbDriverEntry(&req.magic);
	
	return errcode;
}

unsigned long SetVendorID(){
	
	unsigned long errcode = 0;
	RequestResponse req;
	gen_req(&req,MD_SETVID);
	
	memcpy(&req.dog_data,DogData,8);
	
	crypt_request(&req);
	
	errcode = LinuxUsbDriverEntry(&req.magic);
	
	return errcode;
}

#endif