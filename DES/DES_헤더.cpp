#include "DES_���.h"

void DES_Encryption(BYTE* p_text, BYTE* result, BYTE* key) {

}


void DES_Decryption(BYTE* c_text, BYTE* result, BYTE* key) {
	int i;
	BYTE data[BLOCK_SIZE] = { 0, };
	BYTE round_key[16][6] = { 0, };
	UINT L = 0, R = 0;

	/* ���� Ű ���� */
	Key_Expansion(key, round_key);

	for (int j = 0; j < 16; j++) {
		bitset<6> x((int)round_key[j]);
		// cout << "ROUDN_KEY[" << j << "] :: \t" << x << endl;
	}
	// cout << endl;
	/* �ʱ� ���� */
	IP(c_text, data);

	/* 64bit ����� 32bit�� ���� */
	BtoW(data, &L, &R);

	/* DES Round 1~16 */
	for (i = 0; i < DES_ROUND; i++) {
		/* ��ȣȭ�� ���ؼ� ����Ű�� �������� ���� */
		L = L ^ f(R, round_key[DES_ROUND - i - 1]);

		/* ������ ����� Swap�� ���� �ʴ´�. */
		if (i != DES_ROUND - 1) {
			Swap(&L, &R);
		}
		bitset<32> x((int)L);
		bitset<32> y((int)R);
		// cout << "L[" << i << "]" << x << "\t" << "R[" << i << "]" << y << endl;
	}

	for (int i = 0; i < 8; i++)
		data[i] = 0;

	/* 32bit�� �������� ����� �ٽ� 64bit ������� ��ȯ */
	WtoB(L, R, data);

	/* �� �ʱ� ���� */
	IIP(data, result);
	// cout << endl << endl << "��ȣȭ ���" << endl;
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
		/* EP���̺��� ��Ÿ���� ��ġ�� ��Ʈ���� & ����� ����Ʈ ������ �̿��Ͽ� ���� */
		if (Right32 & (bit32_Mask >> (E[i] - 1))) {
			/* ������ ���� �迭�� ���� ��Ʈ���� ���� */
			out[i / 8] |= (BYTE)(bit8_Mask >> (i % 8));
		}
	}
	return;
}

UINT S_Box_Transfer(BYTE* in) {
	int i, row, column, shift = 28;
	UINT temp = 0, result = 0, mask = 0x00000080;
	for (i = 0; i < 48; i++) {
		/* �Է°��� ���� ��Ʈ���� 1��Ʈ�� ���ʷ� �����Ͽ� temp�� ���� */
		if (in[i / 8] & (BYTE)(mask >> (i % 8))) {
			temp |= 0x20 >> (i % 6);
		}
		else
			;

		/* ������ ��Ʈ�� 6��Ʈ�� �Ǹ� */
		if ((i + 1) % 6 == 0) {
			row = ((temp & 0x20) >> 4) + (temp & 0x01); /* ���� ���� ���*/
			column = (temp & 0x1E) >> 1; /* ���� ���� ���*/
										 /* 4��Ʈ�� ��� ���� result�� ���� ��Ʈ���� 4��Ʈ�� ���� */
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
		/* ���� ���̺��� ��Ÿ���� ��ġ�� ��Ʈ�� ������ ��� ���� ���� ��Ʈ���� ���� */
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

	/* PC-1�� ��Ÿ���� ��ġ�� ����Ͽ� �Է°����κ��� �ش� ��ġ�� ��Ʈ�� �����ϰ� ������� ������ �迭�� ���� ��Ʈ���� ���� */
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
		n = (n << 1) + (n >> 27); /* 28bit ��ȿ �ڸ����� ����� circulation shift */
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

	/* PC-2�� ��Ÿ���� ��ġ�� ����Ͽ� �Է°����κ��� �ش� ��ġ�� ��Ʈ�� �����Ͽ� ������� ������ �迭�� ���� ��Ʈ���� ���� */
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