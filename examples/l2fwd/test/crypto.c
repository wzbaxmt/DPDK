#include "aes.h"
#include "crypto.h"
#include "sm4.h"

#define SM4_BLOCK_SIZE	16
#define QKEY_DEBUG printf
static void TestPrintBuffer(const char *pBuff1, int nLen)
{
	int i;
	for(i=0; i<nLen; i++)
	{
		printf("%02x\n", pBuff1[i] & 0x000000FF);
	}
}

//PKCS#7
int PaddingData(BYTE *pInData, int nInDataLen)
{
	int i = 0;
	int paddingLen = SM4_BLOCK_SIZE - nInDataLen % SM4_BLOCK_SIZE;
	for (i = 0; i < paddingLen; i++)
	{
		*(pInData +  nInDataLen + i) = paddingLen;
	}
	return nInDataLen + paddingLen;
}


int GetPaddingDataLen(BYTE *pInData, int nInDataLen)
{
	return (int)*(pInData + nInDataLen - 1);
}



//key len is 32Bit
int AesEncrypt(BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	aes_context aes;
	BYTE iv[16] = { 0 };
	int nRet = 0, nDataPadd = 0;
	if(InKeyLen != 32 || InSource == 0 || InSourceLen ==0 || OutDest == 0)
		return -1;

	aes_setkey_enc(&aes, InKey, InKeyLen*8);
	nDataPadd = PaddingData(InSource, InSourceLen);
	nRet = aes_crypt_cbc(&aes, AES_ENCRYPT, nDataPadd, iv, InSource, OutDest);
	if(nRet != 0)
	{
		QKEY_DEBUG("AesEncrypt aes_crypt_cbc error!nDataPadd = %ld, nRet = %d\n", nDataPadd, nRet);
		return -1;
	}

	*OutDestLen = nDataPadd;

	return 0;
}

int AesDecrypt(BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	int nRet = 0;
	aes_context aes;
	BYTE iv[16] = { 0 };
	if(InKeyLen != 32 || InSource == 0 || InSourceLen ==0 || OutDest == 0)
		return -1;

	aes_setkey_dec(&aes, InKey, InKeyLen*8);
	nRet = aes_crypt_cbc(&aes, AES_DECRYPT, InSourceLen, iv, InSource, OutDest);
	if(nRet != 0)
	{
		QKEY_DEBUG("AesDecrypt aes_crypt_cbc error!nRet = %d\n", nRet);
		return -1;
	}

	*OutDestLen = InSourceLen - GetPaddingDataLen(OutDest, InSourceLen);

	return 0;
}
int SM4Encrypt(BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	sm4_context ctx;
	int nRet = 0, nDataPadd = 0;
	if(InKeyLen != 32 || InSource == 0 || InSourceLen ==0 || OutDest == 0)
		return -1;

	sm4_setkey_enc(&ctx,InKey);

	nDataPadd = PaddingData(InSource, InSourceLen);
	printHex(InSource, nDataPadd, 0, "SM4Encrypt before");
	sm4_crypt_ecb(&ctx, 1, nDataPadd, InSource, OutDest);

	*OutDestLen = nDataPadd;
	printHex(OutDest, *OutDestLen, 0, "SM4Encrypt after");
	return 0;
}

int SM4Decrypt(BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	sm4_context ctx;
	int nRet = 0, nDataPadd = 0;
	if(InKeyLen != 32 || InSource == 0 || InSourceLen ==0 || OutDest == 0)
		return -1;

	sm4_setkey_dec(&ctx,InKey);
	sm4_crypt_ecb(&ctx,0, InSourceLen, InSource, OutDest);
	
	*OutDestLen = InSourceLen - GetPaddingDataLen(OutDest, InSourceLen);
	printHex(OutDest, *OutDestLen, InSourceLen - *OutDestLen, "SM4Decrypt after");
	return 0;
}
int Encrypt(CryptTypeE eType, BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	if(eType >= CRYPTO_MAX || eType <= CRYPTO_NULL)
		return -1;
	switch(eType){
		case CRYPTO_AES_CBC:
			return AesEncrypt(InSource, InSourceLen, OutDest, OutDestLen, InKey, InKeyLen);
        case CRYPTO_SM4_ECB:
			return SM4Encrypt(InSource, InSourceLen, OutDest, OutDestLen, InKey, InKeyLen);

		default:
			break;
	}

	return 0;
}

int Decrypt(CryptTypeE eType, BYTE *InSource, int InSourceLen, BYTE *OutDest, int *OutDestLen, BYTE *InKey, int InKeyLen)
{
	if(eType >= CRYPTO_MAX || eType <= CRYPTO_NULL)
		return -1;
	printHex(InSource, InSourceLen, 0, "Decrypt before");
	switch(eType){
		case CRYPTO_AES_CBC:
			return AesDecrypt(InSource, InSourceLen, OutDest, OutDestLen, InKey, InKeyLen);
        case CRYPTO_SM4_ECB:
			return SM4Decrypt(InSource, InSourceLen, OutDest, OutDestLen, InKey, InKeyLen);

		default:
			break;
	}
	
	return 0;
}

