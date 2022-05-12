#include "BlockCipherMode.h"

void DES_CBC_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE encryptInput[BLOCK_SIZE] = { 0, };
	BYTE encryptOutput[BLOCK_SIZE] = { 0, };

	memcpy(encryptOutput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			encryptInput[byteIndex] = (plainText[byteIndex + blockNum * BLOCK_SIZE] ^ encryptOutput[byteIndex]);
		}

		DES_Encryption(encryptInput, encryptOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			cipherText[byteIndex + blockNum * BLOCK_SIZE] = encryptOutput[byteIndex];
		}
	}
}

void DES_CFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{	
	uint32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			cipherText[byteIndex + blockNum * BLOCK_SIZE] =
				plainText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];
			blockInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_OFB_Enc(BYTE* plainText, BYTE* cipherText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;

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

void DES_CTR_Enc(BYTE* plainText, BYTE* cipherText, UINT64 ctr, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;
	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };
	
	WtoB(ctr, blockNum, blockInput);
	
	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			cipherText[byteIndex + blockNum * BLOCK_SIZE] =
				plainText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];
		}

		blockInput[BLOCK_SIZE - 1]++;
	}
}

void DES_CBC_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE prevCipherBlock[BLOCK_SIZE] = { 0, };
	BYTE decryptInput[BLOCK_SIZE] = { 0, };
	BYTE decryptOutput[BLOCK_SIZE] = { 0, };

	memcpy(prevCipherBlock, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			decryptInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}

		DES_Decryption2(decryptInput, decryptOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			plainText[byteIndex + blockNum * BLOCK_SIZE] = prevCipherBlock[byteIndex] ^ decryptOutput[byteIndex];
			prevCipherBlock[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_CFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;

	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	memcpy(blockInput, IV, BLOCK_SIZE);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{	
			plainText[byteIndex + blockNum * BLOCK_SIZE] =
				cipherText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];	
			blockInput[byteIndex] = cipherText[byteIndex + blockNum * BLOCK_SIZE];
		}
	}
}

void DES_OFB_Dec(BYTE* cipherText, BYTE* plainText, BYTE* IV, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;

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
			blockOutput[byteIndex] ^= cipherText[byteIndex + blockNum * BLOCK_SIZE];
			plainText[byteIndex + blockNum * BLOCK_SIZE] = blockOutput[byteIndex];
		}
	}
}

void DES_CTR_Dec(BYTE* cipherText, BYTE* plainText, UINT64 ctr, BYTE* key, int32_t msg_len)
{
	uint32_t blockNum = 0, byteIndex = 0;
	const uint32_t blockCount = msg_len / BLOCK_SIZE;

	BYTE blockInput[BLOCK_SIZE] = { 0, };
	BYTE blockOutput[BLOCK_SIZE] = { 0, };

	WtoB(ctr, blockNum, blockInput);

	for (blockNum = 0; blockNum < blockCount; ++blockNum)
	{
		DES_Encryption(blockInput, blockOutput, key);

		for (byteIndex = 0; byteIndex < BLOCK_SIZE; ++byteIndex)
		{
			plainText[byteIndex + blockNum * BLOCK_SIZE] =
				cipherText[byteIndex + blockNum * BLOCK_SIZE] ^ blockOutput[byteIndex];
		}

		blockInput[BLOCK_SIZE - 1]++;
	}
}
