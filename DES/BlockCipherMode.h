#pragma once
#include "DES_Çì´õ.h"

#define KEY_SIZE 8

void DES_CBC_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Enc(BYTE* plainText, BYTE* cipherText, UINT64 ctr, BYTE* key, int32_t msg_len);

void DES_CBC_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Dec(BYTE* cipherText, BYTE* plainText, UINT64 counter, BYTE* key, int32_t msg_len);