/*------------------------------------------------------*/
/* Trace functions                                      */
/*                                                      */
/* Crypto.h                                    */
/*                                                      */
/* Copyright (C) QTEC Inc.                              */
/* All rights reserved                                  */
/*                                                      */
/* Author                                               */
/*    pengwb (pengwb@qtec.cn)                           */
/*                                                      */
/* History                                              */
/*    2017/11/09  Create                                */
/*                                                      */
/*------------------------------------------------------*/

//#include "QkeyDefines.h"

#ifndef Q_CRYPTO_H
#define Q_CRYPTO_H

typedef char BYTE;

typedef enum CryptTypeEm{
	CRYPTO_NULL = 0,
	CRYPTO_AES_CBC = 1,
	CRYPTO_SM4_ECB = 6,
	CRYPTO_MAX
}CryptTypeE;

typedef enum HashTypeEm{
	HASH_NULL = 0,
	HASH_256,
	HASH_SM3,
	HASH_MAX
}HashTypeE;

enum SM4Algorithm{
	SM4_ECB_DEC = 0,
	SM4_ECB_ENC,
	SM4_CBC_ENC,
	SM4_CBC_DEC,
};

int Encrypt(CryptTypeE eType, BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen);

int Decrypt(CryptTypeE eType, BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen);

#endif
