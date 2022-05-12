#pragma once

#include <iostream>
#include <bitset>

using namespace std;

#define BLOCK_SIZE 8
#define DES_ROUND 16

typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long long UINT64;

extern int ip[64];
extern int iip[64];
extern int E[48];
extern int s_box[8][4][16];
extern int P[32];
extern int PC_1[56];
extern int PC_2[48];

void PC2(UINT c, UINT d, BYTE* Key_Out);
UINT Cir_Shift(UINT n, int r);
void makeBit28(UINT* c, UINT* d, BYTE* Key_Out);
void PC1(BYTE* Key_In, BYTE* Key_Out);
void Key_Expansion(BYTE* key, BYTE round_key[DES_ROUND][6]);
void WtoB(UINT Left32, UINT Right32, BYTE* out);
void Swap(UINT* x, UINT* y);
UINT Permutation(UINT in);
UINT S_Box_Transfer(BYTE* in);
void EP(UINT Right32, BYTE* out);
UINT f(UINT Right32, BYTE* rKey);
void BtoW(BYTE* Plain64, UINT* Left32, UINT* Right32);
void IIP(BYTE* in, BYTE* out);
void IP(BYTE* in, BYTE* out);
void DES_Decryption(BYTE* c_text, BYTE* result, BYTE* key);
void DES_Encryption(BYTE* p_text, BYTE* result, BYTE* key);

void DES_Decryption2(BYTE* c_text, BYTE* result, BYTE* key);