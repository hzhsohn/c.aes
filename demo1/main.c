#include "aes.h"
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
    aesGenTables();

    aesStrtoHex(str,key);//���ַ�ת��16����
    aesHextoStr(key,str);  //just to test these two functions

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
        aesGKey(nb,nk,key);
        printf("Plain=   ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
        aesEncrypt(block);
        printf("�̶�%d�ֽ�,Encrypt= ",nb*4);
        for (i=0;i<nb*4;i++) printf("%02x",(unsigned char)block[i]);
        printf("\n");
        aesDecrypt(block);
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
		aesGKey(nb,nk,key);
		dstLen=aesEncryptData(block,strlen(block),dstBuff,sizeof(dstBuff));
		printf("%d�ֽ�,Encrypt= ",dstLen);
		for (i=0;i<dstLen;i++) printf("%02x",(unsigned char)dstBuff[i]);
			printf("\n");
		aesDecryptData(dstBuff,sizeof(dstBuff));
		printf("%s\n",block);
	}

	//CBCģʽ
	{
		char *pData;
		int pDataLen;
		char iv[32];
		char buf[1024];

		//����ʱǰ�����IV��ʼ��������Ϣ
		char data[]="GJdECjI0/Ig7zzlpPI/Bk7wd3G7EoFPj3MBtWQym87nyaUhOzUXWr+6ALKNXo9QhSwY2yiGRtd8+fRDC6OsLFMpyysZzHuyihVjRBDNMeWDR1JMI+BGAgTHQM6Ll1hJkFkFPR0/fbUUSlrUF40ChKfZFtDfSsZ2SWfljnme1WIY=";
		pDataLen=base64Decode(data,sizeof(data),&pData);

		//����IV��������
		memcpy(iv,pData,sizeof(iv));
		pDataLen-=32;
		memmove(pData,&pData[32],pDataLen);

		nb=8;
		nk=8;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//ydm-0412��MD5
		strcpy(key,"7bd89f2325ca6afb1eec2b2c07e9006c");
		aesGKey(nb,nk,key);
		aesDecryptCBC(iv,sizeof(iv),pData,pDataLen);
		printf("%s\n",pData);

		//-------�ٴμ����ٽ���-----------
		nb=6;
		nk=6;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		aesGKey(nb,nk,key);
		pDataLen=aesEncryptCBC(iv,sizeof(iv),pData,strlen(pData),buf,sizeof(buf));
		printf("%s\n",buf);
		aesDecryptCBC(iv,sizeof(iv),buf,pDataLen);
		printf("%s\n",buf);

		free(pData);
		pData=NULL;
	}

	getchar();
    return 0;
}

