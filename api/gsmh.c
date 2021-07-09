#include <memory.h>
#include <stdlib.h>

#include "../protocol/protocol.h"
#include "../common/utils.h"
#include "gsmh.h"

#include <stdio.h>

// Internal Stuff
static unsigned int bShareStatus_2 = 1;

void InitReqRes(MDGRequest* req, MDGResponse* res, unsigned int operation_code){
    memset(req,0x00,sizeof(MDGRequest));
    memset(res,0x00,sizeof(MDGResponse));
    req->magic = PACKET_MAGIC;
    req->operation_code = operation_code;
    SetTimestamp(&req->ts);
}


#ifdef API_VERSION_4
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static unsigned int iUsbPassAuth = 0;
unsigned int EnableShare();
unsigned int GetDogId();
unsigned int ExternalAuthenicateApplication();
unsigned int InternalAuthenicateApplication();


unsigned int LinuxUsbDriverEntry(MDGRequest * greq, MDGResponse* gres, unsigned int bypass_auth);

unsigned int libExchangeMsgWithDaemon(unsigned char* request_data, unsigned char* response_data){
    unsigned char packet_data[596] = {0x00};
    // Packet Header Version
    *(unsigned int*)packet_data = 0x11;
    memcpy(packet_data+4,request_data,304);


    struct sockaddr_un svr_addr;
    struct sockaddr_un local_addr;

    int fd;
    fd = socket(AF_UNIX, SOCK_DGRAM,0);

    memset(&svr_addr, 0, sizeof(struct sockaddr_un));
    svr_addr.sun_family = AF_UNIX;
    strncpy(svr_addr.sun_path, "/var/run/microdog/u.daemon", sizeof(svr_addr.sun_path) - 1);

    char local_path[16]={0x00};
    strcpy(local_path,"/tmp/u.XXXXXX");
    int th = mkstemp(local_path);
    close(th);
    unlink(local_path);
    memset(&local_addr, 0x00,sizeof(struct sockaddr_un));
    local_addr.sun_family = AF_UNIX;
    strncpy(local_addr.sun_path, local_path, sizeof(local_addr.sun_path) - 1);

    if(bind(fd, (const struct sockaddr*)&local_addr, sizeof(struct sockaddr_un)) == -1){
     DEBUG_PRINT("localsocket Bind Fail!\n");
     return -1;
    }

    unsigned int addrsz = sizeof(struct sockaddr_un);
    if(sendto(fd,packet_data,sizeof(packet_data),0,(const struct sockaddr*)&svr_addr,addrsz) != sizeof(packet_data)){
        DEBUG_PRINT("[gsmh] Packet Send Fail!\n");
     return -1;
    }
    fd_set read_fds;
    fd_set write_fds;
    fd_set except_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(fd, &read_fds);
    if(select(fd + 1, &read_fds, &write_fds, &except_fds, NULL) == -1){
        DEBUG_PRINT("[gsmh] Packet Select Fail!\n");
        return -1;
    }

    if(recvfrom(fd,packet_data,sizeof(packet_data),0,(struct sockaddr*)&svr_addr,&addrsz) != sizeof(packet_data)){
        DEBUG_PRINT("[gsmh] Packet Recv Fail!\n");
        return -1;
    }
    unlink(local_path);
    close(fd);
    memcpy(response_data,packet_data+308,288);
    return *(unsigned int*)packet_data;
}



unsigned int AuthenicateUsbDriver(){
    unsigned int status = EnableShare(1);
    if(status){return status;}
    status = ExternalAuthenicateApplication();
    if(status){return status;}
    status = InternalAuthenicateApplication();
    if(status){return status;}
    // This is ... technically not exactly here but it works.
    status = GetDogId();
    if(status){return status;}
    // Generally, we would check the given DogId against the API here and throw
    // Error 40001 if it doesn't match, but we're going to skip that.
    return status;
}

unsigned int LinuxUsbDriverEntry(MDGRequest * greq, MDGResponse* gres, unsigned int bypass_auth){

    unsigned int status = 0;
    if(!bypass_auth){
        if (!iUsbPassAuth){
            status = AuthenicateUsbDriver();
            if(status){return status;}
        }
        iUsbPassAuth = 1;
    }

    // Convert Request
    GenerateAesMonthKey(greq->session_key);
    unsigned char request_buffer[304] = {0x00};
    unsigned char response_buffer[288] = {0x00};
    PrintRequestInfo(greq);
    EncryptRequest(greq,request_buffer);
    status = libExchangeMsgWithDaemon(request_buffer,response_buffer);
    // Set Response
    DecryptResponse(response_buffer,greq->session_key,gres);
    PrintResponseInfo(gres);
    return status;
}



#else // Handling Logic for API 3.x Goes Here...
unsigned int LinuxUsbDriverEntry(MDGRequest * greq, MDGResponse* gres, unsigned int bypass_auth){
    
}
#endif

// Undocumented API Calls
unsigned int GetDogId(){
    MDGRequest req;
    MDGResponse res;
    InitReqRes(&req,&res,OP_GET_ID);
    unsigned int result = LinuxUsbDriverEntry(&req,&res,1);
    if(result){return result;}
    return res.status_code;
}

unsigned int EnableShare(unsigned int bypass_auth){
    DEBUG_PRINT("EnableShare()\n");
    MDGRequest req;
    MDGResponse res;
    InitReqRes(&req,&res,OP_ENABLE_SHARE);
#ifdef API_VERSION_4
    if(bypass_auth){
        LinuxUsbDriverEntry(&req,&res,1);
        return res.status_code;
    }
    // 0x65 is only used for bypass auth.
    req.operation_code = OP_SET_SHARE;
#endif
    if ( bShareStatus_2 == 1 && !LinuxUsbDriverEntry(&req,&res,0)){
        bShareStatus_2 = 2;
    }
    return res.status_code;
}


unsigned int InternalAuthenicateApplication(){
    MDGRequest req;
    MDGResponse res;
    InitReqRes(&req,&res,OP_VALIDATE_SERVER);
    unsigned char challenge_data[16] = {0x00};
    LinuxUsbDriverEntry(&req,&res,1);
    EncryptWithAesMonthKey(challenge_data,16);
    if(!res.status_code){
        if(memcmp(challenge_data,res.dog_data,16)){
            return ERR_AUTH_SERVER;
        }
    }
    return res.status_code;
}

unsigned int ExternalAuthenicateApplication(){
    MDGRequest req;
    MDGResponse res;
    unsigned int result = 0;
    InitReqRes(&req,&res,OP_VALIDATE_CLIENT);
    unsigned char challenge_data[16] = {0x00};
    EncryptWithAesMonthKey(challenge_data,16);
    memcpy(req.dog_data,challenge_data,16);
    req.dog_bytes = 16;
    result = LinuxUsbDriverEntry(&req,&res,1);
    if(result){return result;}
    return res.status_code;
}

// Exposed API Calls
unsigned int DogCheck(void){
    MDGRequest req;
    MDGResponse res;
    unsigned int result = 0;
    InitReqRes(&req,&res,OP_CHECK);
    result = LinuxUsbDriverEntry(&req,&res,0);
    if(result){return result;}
    return res.status_code;
}
unsigned int ReadDog(void){
    unsigned int result = EnableShare(0);
    if(!result){
        MDGRequest req;
        MDGResponse res;
        InitReqRes(&req,&res,OP_READ);
        req.dog_bytes = DogBytes;
        req.dog_addr = DogAddr;
        req.dog_password = DogPassword;
        result = LinuxUsbDriverEntry(&req,&res,0);
        if(result){return result;}
        if(!res.status_code){
            memcpy(DogData,req.dog_data,DogBytes);
        }
        return res.status_code;
    }
    return result;
}

unsigned int DogConvert(void){

    unsigned int result = EnableShare(0);
    if(!result){
        DEBUG_PRINT("DogConvert()\n");
        MDGRequest req;
        MDGResponse res;
        InitReqRes(&req,&res,0);
#ifdef API_VERSION_4
      req.operation_code = OP_CONVERT_HASH;
      req.dog_bytes = 16;
      unsigned char dog_hash[16] = {0x00};
      md5_hash(dog_hash,DogData,DogBytes);
      memcpy(req.dog_data,dog_hash,16);
#else
    req.operation_code = OP_CONVERT;
    memcpy(req.dog_data,DogData,DogBytes);
    req.dog_bytes = DogBytes;
#endif
        result = LinuxUsbDriverEntry(&req,&res,0);
        if(result){return result;}
        if(!res.status_code){
            memcpy(&DogResult,res.dog_data,4);
        }
        return res.status_code;
    }
    return result;
}
unsigned int WriteDog(void){
    unsigned int result = EnableShare(0);
    if(!result){
        MDGRequest req;
        MDGResponse res;
        InitReqRes(&req,&res,OP_WRITE);
        req.dog_bytes = DogBytes;
        req.dog_addr = DogAddr;
        req.dog_password = DogPassword;
        memcpy(req.dog_data,DogData,DogBytes);

        result = LinuxUsbDriverEntry(&req,&res,0);
        if(result){return result;}
        return res.status_code;
    }
    return result;
}
unsigned int GetCurrentNo(void){
    unsigned int result = 0;
    MDGRequest req;
    MDGResponse res;
    InitReqRes(&req,&res,OP_GET_MFG_SERIAL);
    result = LinuxUsbDriverEntry(&req,&res,0);
    if(result){return result;}
    if(!res.status_code){
        memcpy(DogData,res.dog_data,4);
    }
    return res.status_code;
}

unsigned int SetDogCascade(void){
    unsigned int result = EnableShare(0);
    if(!result){
        MDGRequest req;
        MDGResponse res;
        InitReqRes(&req,&res,OP_SET_CASCADE);
        req.dog_data[0] = DogCascade;
        req.dog_bytes = 1;
        result = LinuxUsbDriverEntry(&req,&res,0);
        if(result){return result;}
        return res.status_code;
    }
    return result;
}

unsigned int SetPassword(void){
    unsigned int result = EnableShare(0);
    if(!result){
        MDGRequest req;
        MDGResponse res;
        InitReqRes(&req,&res,OP_SET_PWD);
        req.dog_password = DogPassword;
        memcpy(req.dog_data,&NewPassword,4);
        req.dog_bytes = 4;
        result = LinuxUsbDriverEntry(&req,&res,0);
        if(result){return result;}
        return res.status_code;
    }
    return result;
}