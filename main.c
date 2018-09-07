#include "../aes.h"
#include "tchar.h"
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
		char *pData;
		int pDataLen;
		const char iv[32]="0102030405060708AABBCCDDEEFFGGHH"; //����ƫ����,���Զ���
		char buf[1024];

		//����ʱǰ�����IV��ʼ��������Ϣ
		char data[]="yhB1ODGomlPGf4IPk7v2VSAFPox0hCGdGODm7xNDWGwFBfyuSGdwPJnU2/ql15YbORKwx3/D3QcjpPr6U8kFNuZtFW4jW0FBMIWNGbCylYa3IMpmjDwC2+JTv4mHJ+j/NcNC6dg+UWNpz4JRlt2kvSv7xqYxU4Q2o3uzR77TDKo=";
		
		pData=malloc(sizeof(data)*1.5f);
		pDataLen=zhBase64Encode(data,sizeof(data),pData);

		
		nb=8;
		nk=8;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//0412��MD5
		strcpy(key,"69a829ce4f4e0d631ca634a866590a60");
		zhAesGKey(nb,nk,key);
		zhAesDecryptCBC(iv,sizeof(iv),pData,pDataLen);
		printf("%s\n",pData);

		//-------�ٴμ����ٽ���-----------
		nb=6;
		nk=6;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		zhAesGKey(nb,nk,key);
		pDataLen=zhAesEncryptCBC(iv,sizeof(iv),pData,strlen(pData),buf,sizeof(buf));
		printf("���ܺ�:%s\n",buf);
		zhAesDecryptCBC(iv,sizeof(iv),buf,pDataLen);
		printf("���ܺ�:%s\n",buf);

		free(pData);
		pData=NULL;
	}

	getchar();
    return 0;
}

