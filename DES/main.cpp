#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "BlockCipherMode.h"
#pragma warning(disable:4996)

#define BUF_SIZE 128
#define BLOCK_MODE 1	/* 1: CBC, 2: CFB, 3: OFB, 4: CTR */

void ClearReadBuffer(void)
{
    while (getchar() != '\n');
}

int main()
{
    int32_t i;
    BYTE p_text[BUF_SIZE] = { 0, };
    BYTE key[KEY_SIZE + 1] = { 0, };
    BYTE IV[BLOCK_SIZE + 1] = { 0, };
    BYTE c_text[BUF_SIZE] = { 0, };
    BYTE d_text[BUF_SIZE] = { 0, };
    int32_t msg_len;
    UINT64 ctr = 0;

#define TEST false
#if(TEST)
    strcpy((char*)p_text, "Computer Security");
    strcpy((char*)key, "security");
    strcpy((char*)IV, "iloveyou");
    ctr = 0x12345678;
#else
    /* �� �Է� */
    printf("�� �Է� : ");
    fgets((char*)p_text, BUF_SIZE, stdin);
    p_text[strlen((char*)p_text) - 1] = '\0';

    /* ���Ű �Է� */
    printf("���Ű �Է� : ");
    scanf_s("%8s", key, KEY_SIZE + 1);
    //ClearReadBuffer();

#if(BLOCK_MODE != 4)
    /* �ʱ�ȭ ���� �Է� */
    printf("�ʱ�ȭ ���� �Է� : ");
    scanf_s("%8s", IV, BLOCK_SIZE + 1);
    //ClearReadBuffer();
#else
    /* ī���� �Է� */
    printf("ctr �Է�: ");
    scanf_s("%lld", &ctr, sizeof(UINT64));
    ClearReadBuffer();
#endif
#endif

    /* �޽��� ���� ��� */
    msg_len = (strlen((char*)p_text) % BLOCK_SIZE) ?
        ((strlen((char*)p_text) / BLOCK_SIZE + 1) * BLOCK_SIZE) : strlen((char*)p_text);

#if(BLOCK_MODE == 0)
    DES_ECB_Enc(p_text, c_text, IV, key, msg_len);
#elif(BLOCK_MODE == 1)
    DES_CBC_Enc(p_text, c_text, IV, key, msg_len); //DES-CBC ��ȣȭ
#elif(BLOCK_MODE == 2)
    DES_CFB_Enc(p_text, c_text, IV, key, msg_len); //DES-CFB ��ȣȭ
#elif(BLOCK_MODE == 3)
    DES_OFB_Enc(p_text, c_text, IV, key, msg_len); //DES-OFB ��ȣȭ
#else
    DES_CTR_Enc(p_text, c_text, ctr, key, msg_len);//DES-CTR ��ȣȭ
#endif


/* ��ȣ�� ��� */
    printf("\n��ȣ��: ");
    for (i = 0; i < msg_len; i++)
        printf("%02x ", c_text[i]);
    printf("\n");

#if(BLOCK_MODE == 0)
    DES_ECB_Dec(c_text, d_text, IV, key, msg_len);
#elif(BLOCK_MODE == 1)
    DES_CBC_Dec(c_text, d_text, IV, key, msg_len);//DES-CBC ��ȣȭ
#elif(BLOCK_MODE == 2)
    DES_CFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB ��ȣȭ
#elif(BLOCK_MODE == 3)
    DES_OFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB ��ȣȭ
#else
    DES_CTR_Dec(c_text, d_text, ctr, key, msg_len);//DES-CTR ��ȣȭ
#endif

/* ��ȣ�� ��� */
    printf("\n��ȣ��: ");
    for (i = 0; i < msg_len; i++)
        printf("%c", d_text[i]);
    printf("\n");

    return 0;
}
