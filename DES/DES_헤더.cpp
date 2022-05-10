#include "DES_헤더.h"

void DES_Encryption(BYTE* p_text, BYTE* result, BYTE* key) {

}


void DES_Decryption(BYTE* c_text, BYTE* result, BYTE* key) {
	int i;
	BYTE data[BLOCK_SIZE] = { 0, };
	BYTE round_key[16][6] = { 0, };
	UINT L = 0, R = 0;

	/* 라운드 키 생성 */
	Key_Expansion(key, round_key);

	for (int j = 0; j < 16; j++) {
		bitset<6> x((int)round_key[j]);
		// cout << "ROUDN_KEY[" << j << "] :: \t" << x << endl;
	}
	// cout << endl;
	/* 초기 순열 */
	IP(c_text, data);

	/* 64bit 블록을 32bit로 나눔 */
	BtoW(data, &L, &R);

	/* DES Round 1~16 */
	for (i = 0; i < DES_ROUND; i++) {
		/* 암호화와 비교해서 라운드키를 역순으로 적용 */
		L = L ^ f(R, round_key[DES_ROUND - i - 1]);

		/* 마지막 라운드는 Swap을 하지 않는다. */
		if (i != DES_ROUND - 1) {
			Swap(&L, &R);
		}
		bitset<32> x((int)L);
		bitset<32> y((int)R);
		// cout << "L[" << i << "]" << x << "\t" << "R[" << i << "]" << y << endl;
	}

	for (int i = 0; i < 8; i++)
		data[i] = 0;

	/* 32bit로 나누어진 블록을 다시 64bit 블록으로 변환 */
	WtoB(L, R, data);

	/* 역 초기 순열 */
	IIP(data, result);
	// cout << endl << endl << "복호화 결과" << endl;
	for (int j = 0; j < 8; j++) {
		bitset<8> x((int)result[j]);
		// cout << j << "\t :: " << x << endl;
	}
}


void IP(BYTE* in, BYTE* out) {
	int i = 0;
	BYTE index, bit, mask = 0x80;

	for (i = 0; i < 64; ++i)
	{
		index = (ip[i] - 1) / 8;
		bit = (ip[i] - 1) % 8;

		if (in[index] & (mask >> bit))
		{
			out[i / 8] |= mask >> (i % 8);
		}
	}
}

void IIP(BYTE* in, BYTE* out) {
	int i = 0;
	BYTE index, bit, mask = 0x80;

	for (i = 0; i < 64; ++i)
	{
		index = (iip[i] - 1) / 8;
		bit = (iip[i] - 1) % 8;

		if (in[index] & (mask >> bit))
		{
			out[i / 8] |= mask >> (i % 8);
		}
	}
}

void BtoW(BYTE* Plain64, UINT* Left32, UINT* Right32) {
	int i = 0;

	for (i = 0; i < 8; ++i)
	{
		if (i < 4)
		{
			*Left32 |= (UINT)Plain64[i] << (32 - ((i + 1) * 8));
		}
		else
		{
			*Right32 |= (UINT)Plain64[i] << (64 - ((i + 1) * 8));
		}
	}
}

UINT f(UINT Right32, BYTE* rKey) {

}

void EP(UINT Right32, BYTE* out) {
	int i;
	UINT bit8_Mask = 0x80, bit32_Mask = 0x80000000;
	for (i = 0; i < 48; i++) {
		/* EP테이블이 나타내는 위치의 비트값을 & 연산과 시프트 연산을 이용하여 추출 */
		if (Right32 & (bit32_Mask >> (E[i] - 1))) {
			/* 추출한 값을 배열의 상위 비트부터 저장 */
			out[i / 8] |= (BYTE)(bit8_Mask >> (i % 8));
		}
	}
	return;
}

UINT S_Box_Transfer(BYTE* in) {
	int i, row, column, shift = 28;
	UINT temp = 0, result = 0, mask = 0x00000080;
	for (i = 0; i < 48; i++) {
		/* 입력값의 상위 비트부터 1비트씩 차례로 추출하여 temp에 저장 */
		if (in[i / 8] & (BYTE)(mask >> (i % 8))) {
			temp |= 0x20 >> (i % 6);
		}
		else
			;

		/* 추출한 비트가 6비트가 되면 */
		if ((i + 1) % 6 == 0) {
			row = ((temp & 0x20) >> 4) + (temp & 0x01); /* 행의 값을 계산*/
			column = (temp & 0x1E) >> 1; /* 열의 값을 계산*/
										 /* 4비트의 결과 값을 result에 상위 비트부터 4비트씩 저장 */
			result += ((UINT)s_box[i / 6][row][column] << shift);
			shift -= 4;
			temp = 0;
		}
	}
	return result;
}

UINT Permutation(UINT in) {
	int i;
	UINT out = 0, mask = 0x80000000;
	for (i = 0; i < 32; i++) {
		/* 순열 테이블이 나타내는 위치의 비트를 추출한 결과 값을 상위 비트부터 저장 */
		if (in & (mask >> (P[i] - 1))) {
			out |= (mask >> i);
		}
		else
			; //do nothing
	}
	return out;
}

void Swap(UINT* x, UINT* y) {
	UINT temp;
	temp = *x;
	*x = *y;
	*y = temp;
}

void WtoB(UINT Left32, UINT Right32, BYTE* out) {

}

void Key_Expansion(BYTE* key, BYTE round_key[16][6]) {

}

void PC1(BYTE* Key_In, BYTE* Key_Out) {
	int i, index, bit;
	UINT mask = 0x00000080;

	/* PC-1이 나타내는 위치를 계산하여 입력값으로부터 해당 위치의 비트를 추출하고 결과값을 저장할 배열에 상위 비트부터 저장 */
	for (i = 0; i < 56; i++) {
		index = (PC_1[i] - 1) / 8;
		bit = (PC_1[i] - 1) % 8;
		if (Key_In[index] & (BYTE)(mask >> bit)) {
			// cout << "i / 8 :: " << i / 8 << "\t i % 8 :: " << i % 8 << endl;
			Key_Out[i / 8] |= (BYTE)(mask >> (i % 8));
		}
		//bitset<8> x((int)Key_Out[i % 8]);
		//cout << "Key_Out[ " << i % 8 << " ] ::: " << Key_Out[i % 8] << " ||| " << x << endl;
	}
}

void makeBit28(UINT* c, UINT* d, BYTE* Key_Out) {
	int i;
	BYTE mask = 0x80;
	for (i = 0; i < 56; i++) {
		if (i < 28) {
			if (Key_Out[i / 8] & (mask >> (i % 8))) {
				*c |= 0x08000000 >> i;
			}
			else
				; // do nothing
		}
		else {
			if (Key_Out[i / 8] & (mask >> (i % 8))) {
				*d |= 0x08000000 >> (i - 28);
			}
			else
				; // do nothing
		}
	}
}

UINT Cir_Shift(UINT n, int r) {
	int n_shift[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
	if (n_shift[r] == 1) {
		n = (n << 1) + (n >> 27); /* 28bit 유효 자릿수에 기반한 circulation shift */
	}
	else {
		n = (n << 2) + (n >> 26);
	}

	n &= 0x0FFFFFFF;
	return n;
}

void PC2(UINT c, UINT d, BYTE* Key_Out) {
	int i;
	UINT mask = 0x08000000;

	/* PC-2가 나타내는 위치를 계산하여 입력값으로부터 해당 위치의 비트를 추출하여 결과값을 저장할 배열에 상위 비트부터 저장 */
	for (i = 0; i < 48; i++) {
		if (PC_2[i] < 28) {
			if (c & (mask >> (PC_2[i] - 1))) {
				Key_Out[i / 8] |= 0x80 >> (i % 8);
			}
			else
				; // do nothing
		}
		else {
			if (d & (mask >> (PC_2[i] - 1 - 28))) {
				Key_Out[i / 8] |= 0x80 >> (i % 8);
			}
			else
				; // do nothing
		}
	}
}