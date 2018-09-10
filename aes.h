#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __aes_h__
#include <stdio.h>

#define BYTE unsigned char       /* 8 bits  */
#define WORD unsigned long       /* 32 bits */

WORD _zhAesPack(BYTE *b);
void _zhAesUnPack(WORD a,BYTE *b);
BYTE _zhAesXtime(BYTE a);
BYTE _zhAesBmul(BYTE x,BYTE y);
WORD _zhAesSubByte(WORD a);
BYTE _zhAesProduct(WORD x,WORD y);
WORD _zhAesInvMixCol(WORD x);
BYTE _zhAesByteSub(BYTE x);

//����AES��
void zhAesGenTables(void);
//MD5ת��
void zhAesStrtoHex(char *str,char *hex);
void zhAesHextoStr(char *hex,char *str);
void zhAesGKey(int nb,int nk,char *key);
/*����16,24,32���ֽ�*/
void zhAesEncrypt(char *buff);
void zhAesDecrypt(char *buff);

/*	�������ݿ�
	����0����dstBuff���Ȳ���
	���ؼӽ��ܺ����ݵĳ���
*/
int zhAesEncryptData(const char *buff,int buffLen,char*dstBuff,int dstBuffLen);
void zhAesDecryptData(char *buff,int buffLen);

/*
	CBCģʽ�ӽ���
*/
int zhAesEncryptCBC(char*iv,int iv_len,char *buff,int buffLen,char*dstBuff,int dstBuffLen);
void zhAesDecryptCBC(char*iv,int iv_len,char *buff,int buffLen);

#define __aes_h__
#endif

#ifdef __cplusplus
}
#endif