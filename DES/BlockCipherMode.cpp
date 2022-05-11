#include "BlockCipherMode.h"

void DES_CBC_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockOutput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			blockOutput[byteIndex] ^= plainText[byteIndex + blockNum * BLOCK_SIZE];
			blockInput[byteIndex] = blockOutput[byteIndex];
		}

		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			cipherText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex];
		}
	}
}

void DES_CFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{	
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			blockOutput[byteIndex] ^= plainText[byteIndex + blockNum * BLOCK_SIZE];
			cipherText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex];
			blockInput[byteIndex] = blockOutput[byteIndex];
		}
	}
}

void DES_OFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			blockInput[byteIndex] = blockOutput[byteIndex];
			blockOutput[byteIndex] ^= plainText[byteIndex + blockNum * BLOCK_SIZE];
			cipherText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex];
		}
	}
}

void DES_CTR_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;
	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockOutput[BLOCK_SIZE] = { 0, };
	std::random_device rd;
	std::mt19937 gen(rd());
	UINT mask = 0xff000000;
	BYTE CTR[BLOCK_SIZE] = { 0, };

	UINT nonce = 0;

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		nonce = gen();

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			if (byteIndex < 4)
			{
				CTR[byteIndex] |= nonce & (mask >> (byteIndex * 8)) >> (32 - (byteIndex + 1) * 8);
			}
			else
			{
				CTR[byteIndex] |= blockNum & (mask >> (byteIndex * 8)) >> (64 - (byteIndex + 1) * 8);
			}
		}

		DES_Encryption(CTR, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			cipherText[byteIndex + blockNum * BLOCK_SIZE] = plainText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];
		}
	}
}

void DES_CBC_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE previousInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(previousInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Decryption(cipherText + blockNum * BLOCK_SIZE, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			plainText[byteIndex + blockNum * BLOCK_SIZE] = previousInput[byteIndex] ^ blockOutput[byteIndex];
			previousInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_CFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			plainText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex] ^ cipherText[byteIndex + blockNum * BLOCK_SIZE];
			blockInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_OFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			blockInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
			plainText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex] ^ cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_CTR_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	int32_t blockNum = 0, byteIndex = 0;
	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockOutput[BLOCK_SIZE] = { 0, };
	std::random_device rd;
	std::mt19937 gen(rd());
	UINT mask = 0xff000000;
	BYTE CTR[BLOCK_SIZE] = { 0, };

	UINT nonce = 0;

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		nonce = gen();

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			if (byteIndex < 4)
			{
				CTR[byteIndex] |= nonce & (mask >> (byteIndex * 8)) >> (32 - (byteIndex + 1) * 8);
			}
			else
			{
				CTR[byteIndex] |= blockNum & (mask >> (byteIndex * 8)) >> (64 - (byteIndex + 1) * 8);
			}
		}

		DES_Encryption(CTR, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			plainText[byteIndex + blockNum * BLOCK_SIZE] = cipherText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];
		}
	}
}
