//###########################################################################
//
//  Module:  GSMH.H
//
//  Decriptions:  This is header file for LINUX API module.
//
//
//  Copyright (C) 2004 SafeNet China Ltd. All Rights Reserved.
//
//###########################################################################

#ifndef _GSMH_H_
#define _GSMH_H_


#ifdef  __cplusplus
extern "C" {
#endif


extern short int DogBytes,DogAddr;
extern unsigned long DogPassword;
extern unsigned long NewPassword;
extern unsigned long DogResult;
extern unsigned char DogCascade;
extern void * DogData;

extern unsigned long DogCheck(void);
extern unsigned long ReadDog(void);
extern unsigned long DogConvert(void);
extern unsigned long WriteDog(void);
extern unsigned long GetCurrentNo(void);
extern unsigned long SetDogCascade(void);
extern unsigned long SetPassword(void);

#ifdef  __cplusplus
}
#endif


#endif //_GSMH_H_
