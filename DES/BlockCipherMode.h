#pragma once
#include "DES.h"

void DES_CBC_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);

void DES_CBC_Dec(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Dec(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Dec(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Dec(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);

