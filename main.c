#include "../aes.h"
#include "tchar.h"
#include <stdlib.h>
#include "c_base64.h"

int main()
{
	/* test driver */
    int i,nb,nk;

	//������Կ��
    char str[]="abcd123456789012345678901234567890121234567890123456789012345678";

	//Կ�״�С�̶�32���ֽ�,���������MD5�ַ���
	char key[33]={0};
	//����
	char block[40]={0};

	printf("Կ�״�С %d\n",strlen(str));

	//��ʼ��
    zhAesGenTables();

    zhAesStrtoHex(str,key);//���ַ�ת��16����
    zhAesHextoStr(key,str);  //just to test these two functions

    printf("Key= ");
    for (i=0;i<64;i++) printf("%c",str[i]);
    printf("\n");

    //Ҫ���ܵ����ݿ�����
    for (i=0;i<sizeof(block);i++) block[i]=i+1;

    for (nb=4;nb<=8;nb+=2)
        for (nk=4;nk<=8;nk+=2)
    {  
        printf("\nBlock Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//��������λ��Կ��λ,������Կ��
        zhAesGKey(nb,nk,key);
        printf("Plain=   ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
        zhAesEncrypt(block);
        printf("�̶�%d�ֽ�,Encrypt= ",nb*4);
        for (i=0;i<nb*4;i++) printf("%02x",(unsigned char)block[i]);
        printf("\n");
        zhAesDecrypt(block);
        printf("Decrypt= ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
    }

	//�������ݿ�
	{
		int dstLen;
		char dstBuff[48];

		strcpy(block,"123456789");
		nb=4;
		nk=4;

		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		zhAesGKey(nb,nk,key);
		dstLen=zhAesEncryptData(block,strlen(block),dstBuff,sizeof(dstBuff));
		printf("%d�ֽ�,Encrypt= ",dstLen);
		for (i=0;i<dstLen;i++) printf("%02x",(unsigned char)dstBuff[i]);
			printf("\n");
		zhAesDecryptData(dstBuff,sizeof(dstBuff));
		printf("%s\n",block);
	}

	//CBCģʽ
	{
		char iv[33]="0102030405060708AABBCCDDEEFFGGHH"; //����ƫ����,���Զ���
		int cbcLen;
		char buf[1024];
		char *pData;

		//����ʱǰ�����IV��ʼ��������Ϣ
		char data[]="123456999abc";

		nb=6;
		nk=6;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		zhAesGKey(nb,nk,key);
		cbcLen=zhAesEncryptCBC(iv,32,data,strlen(data),buf,sizeof(buf));

		pData=(char*)malloc(cbcLen*1.5f);
		zhBase64Encode(buf,cbcLen,pData);
		printf("���ܺ�base64: %s\n",pData);
		zhAesDecryptCBC(iv,32,buf,cbcLen);
		printf("���ܺ�: %s\n",buf);

		free(pData);
	}

	getchar();
    return 0;
}

