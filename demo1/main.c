#include "aes.h"
#include "tchar.h"
#include "c_base64.h"

int main()
{
	/* test driver */
    int i,nb,nk;

	//这里是钥匙
    char str[]="abcd123456789012345678901234567890121234567890123456789012345678";

	//钥匙大小固定32个字节,这里可以是MD5字符串
	char key[33]={0};
	//内容
	char block[40]={0};

	printf("钥匙大小 %d\n",strlen(str));

	//初始化
    aesGenTables();

    aesStrtoHex(str,key);//将字符转成16进制
    aesHextoStr(key,str);  //just to test these two functions

    printf("Key= ");
    for (i=0;i<64;i++) printf("%c",str[i]);
    printf("\n");

    //要加密的数据块内容
    for (i=0;i<sizeof(block);i++) block[i]=i+1;

    for (nb=4;nb<=8;nb+=2)
        for (nk=4;nk<=8;nk+=2)
    {  
        printf("\nBlock Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//设置数据位和钥匙位,和数据钥匙
        aesGKey(nb,nk,key);
        printf("Plain=   ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
        aesEncrypt(block);
        printf("固定%d字节,Encrypt= ",nb*4);
        for (i=0;i<nb*4;i++) printf("%02x",(unsigned char)block[i]);
        printf("\n");
        aesDecrypt(block);
        printf("Decrypt= ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
    }

	//加密数据块
	{
		int dstLen;
		char dstBuff[48];

		strcpy(block,"123456789");
		nb=4;
		nk=4;

		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		aesGKey(nb,nk,key);
		dstLen=aesEncryptData(block,strlen(block),dstBuff,sizeof(dstBuff));
		printf("%d字节,Encrypt= ",dstLen);
		for (i=0;i<dstLen;i++) printf("%02x",(unsigned char)dstBuff[i]);
			printf("\n");
		aesDecryptData(dstBuff,sizeof(dstBuff));
		printf("%s\n",block);
	}

	//CBC模式
	{
		char *pData;
		int pDataLen;
		char iv[32];
		char buf[1024];

		//加密时前面带有IV初始化向量信息
		char data[]="GJdECjI0/Ig7zzlpPI/Bk7wd3G7EoFPj3MBtWQym87nyaUhOzUXWr+6ALKNXo9QhSwY2yiGRtd8+fRDC6OsLFMpyysZzHuyihVjRBDNMeWDR1JMI+BGAgTHQM6Ll1hJkFkFPR0/fbUUSlrUF40ChKfZFtDfSsZ2SWfljnme1WIY=";
		pDataLen=base64Decode(data,sizeof(data),&pData);

		//导出IV向量数据
		memcpy(iv,pData,sizeof(iv));
		pDataLen-=32;
		memmove(pData,&pData[32],pDataLen);

		nb=8;
		nk=8;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//ydm-0412的MD5
		strcpy(key,"7bd89f2325ca6afb1eec2b2c07e9006c");
		aesGKey(nb,nk,key);
		aesDecryptCBC(iv,sizeof(iv),pData,pDataLen);
		printf("%s\n",pData);

		//-------再次加密再解密-----------
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

