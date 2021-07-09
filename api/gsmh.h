// Replacement GSMH Microdog Client Library
#pragma once

// Define this to switch between the older v3.4 library and the newer 4.0 library.
#define API_VERSION_4


#ifdef  __cplusplus
extern "C" {
#endif
extern unsigned short DogBytes,DogAddr;
extern unsigned int DogPassword;
extern unsigned int NewPassword;
extern unsigned int DogResult;
extern unsigned char DogCascade;
extern void * DogData;

extern unsigned int DogCheck(void);
extern unsigned int ReadDog(void);
extern unsigned int DogConvert(void);
extern unsigned int WriteDog(void);
extern unsigned int GetCurrentNo(void);
extern unsigned int SetDogCascade(void);
extern unsigned int SetPassword(void);


#ifdef  __cplusplus
}
#endif
