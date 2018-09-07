#include "../aes.h"
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
    zhAesGenTables();

    zhAesStrtoHex(str,key);//将字符转成16进制
    zhAesHextoStr(key,str);  //just to test these two functions

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
        zhAesGKey(nb,nk,key);
        printf("Plain=   ");
        for (i=0;i<sizeof(block);i++) printf("%02x",block[i]);
        printf("\n");
        zhAesEncrypt(block);
        printf("固定%d字节,Encrypt= ",nb*4);
        for (i=0;i<nb*4;i++) printf("%02x",(unsigned char)block[i]);
        printf("\n");
        zhAesDecrypt(block);
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
		zhAesGKey(nb,nk,key);
		dstLen=zhAesEncryptData(block,strlen(block),dstBuff,sizeof(dstBuff));
		printf("%d字节,Encrypt= ",dstLen);
		for (i=0;i<dstLen;i++) printf("%02x",(unsigned char)dstBuff[i]);
			printf("\n");
		zhAesDecryptData(dstBuff,sizeof(dstBuff));
		printf("%s\n",block);
	}

	//CBC模式
	{
		char *pData;
		int pDataLen;
		const char iv[32]="0102030405060708AABBCCDDEEFFGGHH"; //加密偏移量,可自定义
		char buf[1024];

		//加密时前面带有IV初始化向量信息
		char data[]="yhB1ODGomlPGf4IPk7v2VSAFPox0hCGdGODm7xNDWGwFBfyuSGdwPJnU2/ql15YbORKwx3/D3QcjpPr6U8kFNuZtFW4jW0FBMIWNGbCylYa3IMpmjDwC2+JTv4mHJ+j/NcNC6dg+UWNpz4JRlt2kvSv7xqYxU4Q2o3uzR77TDKo=";
		
		pData=malloc(sizeof(data)*1.5f);
		pDataLen=zhBase64Encode(data,sizeof(data),pData);

		
		nb=8;
		nk=8;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		//0412的MD5
		strcpy(key,"69a829ce4f4e0d631ca634a866590a60");
		zhAesGKey(nb,nk,key);
		zhAesDecryptCBC(iv,sizeof(iv),pData,pDataLen);
		printf("%s\n",pData);

		//-------再次加密再解密-----------
		nb=6;
		nk=6;
		printf("\nData Size= %d bits, Key Size= %d bits , nb=%d ,nk=%d\n",nb*32,nk*32,nb,nk);
		zhAesGKey(nb,nk,key);
		pDataLen=zhAesEncryptCBC(iv,sizeof(iv),pData,strlen(pData),buf,sizeof(buf));
		printf("加密后:%s\n",buf);
		zhAesDecryptCBC(iv,sizeof(iv),buf,pDataLen);
		printf("解密后:%s\n",buf);

		free(pData);
		pData=NULL;
	}

	getchar();
    return 0;
}

