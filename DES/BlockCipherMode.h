#pragma once
#include "DES_Çì´õ.h"
#include <random>

#define BLOCK_MODE 4	/* 1: CBC, 2: CFB, 3: OFB, 4: CTR */

void DES_CBC_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len);

void DES_CBC_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_OFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);
void DES_CTR_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len);