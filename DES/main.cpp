#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "BlockCipherMode.h"

#define BUF_SIZE 128
#define KEY_SIZE 8

void ClearReadBuffer(void)
{
    while (getchar() != '\n');
}


int main()
{
    int32_t i;
    BYTE p_text[BUF_SIZE] = { 0, };
    BYTE key[KEY_SIZE + 1] = { 0, };
    BYTE IV[KEY_SIZE + 1] = { 0, };
    BYTE c_text[BUF_SIZE] = { 0, };
    BYTE d_text[BUF_SIZE] = { 0, };
    int32_t msg_len;
    UINT64 ctr = 0;

    /* 평문 입력 */
    printf("평문 입력 : ");
    scanf_s("%[^\n]s", p_text, BUF_SIZE);
    ClearReadBuffer();

    /* 비밀키 입력 */
    printf("비밀키 입력 : ");
    scanf_s("%s", key, KEY_SIZE);
    ClearReadBuffer();

#if(BLOCK_MODE != 4)
    /* 초기화 벡터 입력 */
    printf("초기화 벡터 입력 : ");
    scanf_s("%s", IV, KEY_SIZE);
    ClearReadBuffer();
#else
    /* 카운터 입력 */
    printf("ctr 입력: ");
    scanf("%u", &ctr);
#endif

    /* 메시지 길이 계산 */
    msg_len = (strlen((char*)p_text) % BLOCK_SIZE) ?
        ((strlen((char*)p_text) / BLOCK_SIZE + 1) * 8) : strlen((char*)p_text);


#if(BLOCK_MODE == 1)
    DES_CBC_Enc(p_text, c_text, IV, key, msg_len); //DES-CBC 암호화
#elif(BLOCK_MODE == 2)
    DES_CFB_Enc(p_text, c_text, IV, key, msg_len); //DES-CFB 암호화
#elif(BLOCK_MODE == 3)
    DES_OFB_Enc(p_text, c_text, IV, key, msg_len); //DES-OFB 암호화
#else
    DES_CTR_Enc(p_text, c_text, key, ctr, msg_len);//DES-CTR 암호화
#endif


/* 암호문 출력 */
    printf("\n암호문: ");
    for (i = 0; i < msg_len; i++)
        printf("%02x ", c_text[i]);
    printf("\n");

#if(BLOCK_MODE == 1)
    DES_CBC_Dec(c_text, d_text, IV, key, msg_len);//DES-CBC 복호화
#elif(BLOCK_MODE == 2)
    DES_CFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB 복호화
#elif(BLOCK_MODE == 3)
    DES_OFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB 복호화
#else
    DES_CTR_Dec(c_text, d_text, key, ctr, msg_len);//DES-CTR 복호화
#endif

/* 복호문 출력 */
    printf("\n복호문: ");
    for (i = 0; i < msg_len; i++)
        printf("%c", d_text[i]);
    printf("\n");

    return 0;
}
