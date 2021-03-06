#include <stdio.h>
#include "aes.h"
#include <memory.h>

/* rotates x one bit to the left */

#define ROTL(x) (((x)>>7)|((x)<<1))

/* Rotates 32-bit word left by 1, 2 or 3 byte  */

#define ROTL8(x) (((x)<<8)|((x)>>24))
#define ROTL16(x) (((x)<<16)|((x)>>16))
#define ROTL24(x) (((x)<<24)|((x)>>8))

/* Fixed Data */

BYTE InCo[4]={0xB,0xD,0x9,0xE};  /* Inverse Coefficients */

BYTE fbsub[256];
BYTE rbsub[256];
BYTE ptab[256],ltab[256];
WORD ftable[256];
WORD rtable[256];
WORD rco[30];

/* Parameter-dependent data */

int Nk,Nb,Nr;
BYTE fi[24],ri[24];
WORD fkey[120];
WORD rkey[120];

WORD _zhAesPack(BYTE *b)
{ /* _zhAesPack bytes into a 32-bit Word */
    return ((WORD)b[3]<<24)|((WORD)b[2]<<16)|((WORD)b[1]<<8)|(WORD)b[0];
}

void _zhAesUnPack(WORD a,BYTE *b)
{ /* _zhAesUnPack bytes from a word */
    b[0]=(BYTE)a;
    b[1]=(BYTE)(a>>8);
    b[2]=(BYTE)(a>>16);
    b[3]=(BYTE)(a>>24);
}

//关于模多项式0x011b的乘10b运算
BYTE _zhAesXtime(BYTE a)
{
    BYTE b;
    if (a&0x80) b=0x1B;
    else        b=0;
    a<<=1;
    a^=b;
    return a;
}

BYTE _zhAesBmul(BYTE x,BYTE y)
{ /* x.y= AntiLog(Log(x) + Log(y)) */
    if (x && y) return ptab[(ltab[x]+ltab[y])%255];
    else return 0;
}

WORD _zhAesSubByte(WORD a)
{
    BYTE b[4];
    _zhAesUnPack(a,b);
    b[0]=fbsub[b[0]];
    b[1]=fbsub[b[1]];
    b[2]=fbsub[b[2]];
    b[3]=fbsub[b[3]];
    return _zhAesPack(b);    
}

BYTE _zhAesProduct(WORD x,WORD y)
{ /* dot _zhAesProduct of two 4-byte arrays */
    BYTE xb[4],yb[4];
    _zhAesUnPack(x,xb);
    _zhAesUnPack(y,yb); 
    return _zhAesBmul(xb[0],yb[0])^_zhAesBmul(xb[1],yb[1])^_zhAesBmul(xb[2],yb[2])^_zhAesBmul(xb[3],yb[3]);
}

WORD _zhAesInvMixCol(WORD x)
{ /* matrix Multiplication */
    WORD y,m;
    BYTE b[4];

    m=_zhAesPack(InCo);
    b[3]=_zhAesProduct(m,x);
    m=ROTL24(m);
    b[2]=_zhAesProduct(m,x);
    m=ROTL24(m);
    b[1]=_zhAesProduct(m,x);
    m=ROTL24(m);
    b[0]=_zhAesProduct(m,x);
    y=_zhAesPack(b);
    return y;
}

BYTE _zhAesByteSub(BYTE x)
{
    BYTE y=ptab[255-ltab[x]];  /* multiplicative inverse */
    x=y;  x=ROTL(x);
    y^=x; x=ROTL(x);
    y^=x; x=ROTL(x);
    y^=x; x=ROTL(x);
    y^=x; y^=0x63;
    return y;
}

void zhAesGenTables(void)
{ /* generate tables */
    int i;
    BYTE y,b[4];

  /* use 3 as primitive root to generate power and log tables */

    ltab[0]=0;
    ptab[0]=1;  ltab[1]=0;
    ptab[1]=3;  ltab[3]=1; 
    for (i=2;i<256;i++)
    {
        ptab[i]=ptab[i-1]^_zhAesXtime(ptab[i-1]);
        ltab[ptab[i]]=i;
    }
    
  /* affine transformation:- each bit is xored with itself shifted one bit 
	仿射变换
	*/

    fbsub[0]=0x63;
    rbsub[0x63]=0;
    for (i=1;i<256;i++)
    {
        y=_zhAesByteSub((BYTE)i);
        fbsub[i]=y; rbsub[y]=i;
    }

    for (i=0,y=1;i<30;i++)
    {
        rco[i]=y;
        y=_zhAesXtime(y);
    }

  /* calculate forward and reverse tables */
    for (i=0;i<256;i++)
    {
        y=fbsub[i];
        b[3]=y^_zhAesXtime(y); b[2]=y;
        b[1]=y;          b[0]=_zhAesXtime(y);
        ftable[i]=_zhAesPack(b);

        y=rbsub[i];
        b[3]=_zhAesBmul(InCo[0],y); b[2]=_zhAesBmul(InCo[1],y);
        b[1]=_zhAesBmul(InCo[2],y); b[0]=_zhAesBmul(InCo[3],y);
        rtable[i]=_zhAesPack(b);
    }
}

void zhAesStrtoHex(char *str,char *hex)
{
	char ch;
	int     i=0, by = 0;

   while(i < 64 && *str)        // the maximum key length is 32 bytes(256 bits) and
    {                           // hence at most 64 hexadecimal digits
        ch = toupper(*str++);   // process a hexadecimal digit
 
        if(ch >= '0' && ch <= '9')
            by = (by << 4) + ch - '0';
        else if(ch >= 'A' && ch <= 'F')
            by = (by << 4) + ch - 'A' + 10;
        else                    // error if not hexadecimal
        {
            printf("key must be in hexadecimal notation\n");
            exit(0);
        }

        // store a key byte for each pair of hexadecimal digits
        if(i++ & 1)
            hex[i / 2 - 1] = by & 0xff;	
      }
}
void zhAesHextoStr(char *hex,char *str)
{
    int i=0, by = 0;

   while(i < 32 && *hex)        // the maximum key length is 32 bytes(256 bits) and
    {                           // hence at most 64 hexadecimal digits
        by = *hex ;              // process a hexadecimal digit(high)
 		 by=by>>4 &0x0f;
        if(by >= 0 && by <= 9)
            *str++ = by + '0';
        else if(by >= 0x0A && by <= 0x0F)
            *str++ = by -  10+ 'A';
        by = *hex++;            // process a hexadecimal digit(low)
 		 by=by &0x0f;
        if(by >= 0 && by <= 9)
            *str++ = by + '0';
        else if(by >= 0x0A && by <= 0x0F)
            *str++ = by -  10+ 'A';
		i++;
      }
}


void zhAesGKey(int nb,int nk,char *key)
{ /* blocksize=32*nb bits. Key=32*nk bits */
  /* currently nb,bk = 4, 6 or 8          */
  /* key comes as 4*Nk bytes              */
  /* Key Scheduler. Create expanded encryption key */
    int i,j,k,m,N;
    int C1,C2,C3;
    WORD CipherKey[8];
    
    Nb=nb; Nk=nk;

  /* Nr is number of rounds */
    if (Nb>=Nk) Nr=6+Nb;
    else        Nr=6+Nk;

    C1=1;
    if (Nb<8) { C2=2; C3=3; }
    else      { C2=3; C3=4; }

  /* pre-calculate forward and reverse increments */
    for (m=j=0;j<nb;j++,m+=3)
    {
        fi[m]=(j+C1)%nb;
        fi[m+1]=(j+C2)%nb;
        fi[m+2]=(j+C3)%nb;
        ri[m]=(nb+j-C1)%nb;
        ri[m+1]=(nb+j-C2)%nb;
        ri[m+2]=(nb+j-C3)%nb;
    }

    N=Nb*(Nr+1);
    
    for (i=j=0;i<Nk;i++,j+=4)
    {
        CipherKey[i]=_zhAesPack((BYTE *)&key[j]);
    }
    for (i=0;i<Nk;i++) fkey[i]=CipherKey[i];
    for (j=Nk,k=0;j<N;j+=Nk,k++)
    {
        fkey[j]=fkey[j-Nk]^_zhAesSubByte(ROTL24(fkey[j-1]))^rco[k];
        if (Nk<=6)
        {
            for (i=1;i<Nk && (i+j)<N;i++)
                fkey[i+j]=fkey[i+j-Nk]^fkey[i+j-1];
        }
        else
        {
            for (i=1;i<4 &&(i+j)<N;i++)
                fkey[i+j]=fkey[i+j-Nk]^fkey[i+j-1];
            if ((j+4)<N) fkey[j+4]=fkey[j+4-Nk]^_zhAesSubByte(fkey[j+3]);
            for (i=5;i<Nk && (i+j)<N;i++)
                fkey[i+j]=fkey[i+j-Nk]^fkey[i+j-1];
        }

    }

 /* now for the expanded decrypt key in reverse order */

    for (j=0;j<Nb;j++) rkey[j+N-Nb]=fkey[j]; 
    for (i=Nb;i<N-Nb;i+=Nb)
    {
        k=N-Nb-i;
        for (j=0;j<Nb;j++) rkey[k+j]=_zhAesInvMixCol(fkey[i+j]);
    }
    for (j=N-Nb;j<N;j++) rkey[j-N+Nb]=fkey[j];
}


/* There is an obvious time/space trade-off possible here.     *
 * Instead of just one ftable[], I could have 4, the other     *
 * 3 pre-rotated to save the ROTL8, ROTL16 and ROTL24 overhead */ 

void zhAesEncrypt(char *buff)
{
    int i,j,k,m;
    WORD a[8],b[8],*x,*y,*t;

    for (i=j=0;i<Nb;i++,j+=4)
    {
        a[i]=_zhAesPack((BYTE *)&buff[j]);
        a[i]^=fkey[i];
    }
    k=Nb;
    x=a; y=b;

/* State alternates between a and b */
    for (i=1;i<Nr;i++)
    { /* Nr is number of rounds. May be odd. */

/* if Nb is fixed - unroll this next 
   loop and hard-code in the values of fi[]  */

        for (m=j=0;j<Nb;j++,m+=3)
        { /* deal with each 32-bit element of the State */
          /* This is the time-critical bit */
            y[j]=fkey[k++]^ftable[(BYTE)x[j]]^
                 ROTL8(ftable[(BYTE)(x[fi[m]]>>8)])^
                 ROTL16(ftable[(BYTE)(x[fi[m+1]]>>16)])^
                 ROTL24(ftable[x[fi[m+2]]>>24]);
        }
        t=x; x=y; y=t;      /* swap pointers */
    }

/* Last Round - unroll if possible */ 
    for (m=j=0;j<Nb;j++,m+=3)
    {
        y[j]=fkey[k++]^(WORD)fbsub[(BYTE)x[j]]^
             ROTL8((WORD)fbsub[(BYTE)(x[fi[m]]>>8)])^
             ROTL16((WORD)fbsub[(BYTE)(x[fi[m+1]]>>16)])^
             ROTL24((WORD)fbsub[x[fi[m+2]]>>24]);
    }   
    for (i=j=0;i<Nb;i++,j+=4)
    {
        _zhAesUnPack(y[i],(BYTE *)&buff[j]);
        x[i]=y[i]=0;   /* clean up stack */
    }
    return;
}

void zhAesDecrypt(char *buff)
{
    int i,j,k,m;
    WORD a[8],b[8],*x,*y,*t;

    for (i=j=0;i<Nb;i++,j+=4)
    {
        a[i]=_zhAesPack((BYTE *)&buff[j]);
        a[i]^=rkey[i];
    }
    k=Nb;
    x=a; y=b;

/* State alternates between a and b */
    for (i=1;i<Nr;i++)
    { /* Nr is number of rounds. May be odd. */

/* if Nb is fixed - unroll this next 
   loop and hard-code in the values of ri[]  */

        for (m=j=0;j<Nb;j++,m+=3)
        { /* This is the time-critical bit */
            y[j]=rkey[k++]^rtable[(BYTE)x[j]]^
                 ROTL8(rtable[(BYTE)(x[ri[m]]>>8)])^
                 ROTL16(rtable[(BYTE)(x[ri[m+1]]>>16)])^
                 ROTL24(rtable[x[ri[m+2]]>>24]);
        }
        t=x; x=y; y=t;      /* swap pointers */
    }

/* Last Round - unroll if possible */ 
    for (m=j=0;j<Nb;j++,m+=3)
    {
        y[j]=rkey[k++]^(WORD)rbsub[(BYTE)x[j]]^
             ROTL8((WORD)rbsub[(BYTE)(x[ri[m]]>>8)])^
             ROTL16((WORD)rbsub[(BYTE)(x[ri[m+1]]>>16)])^
             ROTL24((WORD)rbsub[x[ri[m+2]]>>24]);
    }        
    for (i=j=0;i<Nb;i++,j+=4)
    {
        _zhAesUnPack(y[i],(BYTE *)&buff[j]);
        x[i]=y[i]=0;   /* clean up stack */
    }
    return;
}

int zhAesEncryptData(const char *buff,int buffLen,char*dstBuff,int dstBuffLen)
{
	int dst_len;
	int step;
	int i;
	
	step=Nb*4;

	if(dstBuffLen<buffLen)
	{return 0;}

	i=dstBuffLen%step;
	if(dstBuffLen<buffLen+i)
	{return 0;}

	dst_len=0;
	memset(dstBuff,0,dstBuffLen);
	memcpy(dstBuff,buff,buffLen);
	for(i=0;i<buffLen;i+=step)
	{
		zhAesEncrypt(&dstBuff[i]);
		dst_len+=step;
	}
	return dst_len;
}

void zhAesDecryptData(char *buff,int buffLen)
{
	int step;
	int i;
	step=Nb*4;
	for(i=0;i<buffLen;i+=step)
	{
		zhAesDecrypt(&buff[i]);
	}
}

int zhAesEncryptCBC(char*iv,int iv_len,char *buff,int buffLen,char*dstBuff,int dstBuffLen)
{
	int i;
	int k;
	int dst_len;
	short step;
	char tmp_iv[32];
	
	step=Nb*4;

	if(dstBuffLen<buffLen)
	{return 0;}

	i=dstBuffLen%step;
	if(dstBuffLen<buffLen+i)
	{return 0;}

	memcpy(tmp_iv,iv,step);
	dst_len=0;
	memset(dstBuff,0,dstBuffLen);
	memcpy(dstBuff,buff,buffLen);
	for(i=0;i<buffLen;i+=step)
	{
		for(k=0;k<step;k++)
		{
			dstBuff[i+k]=dstBuff[i+k]^tmp_iv[k];
		}
		zhAesEncrypt(dstBuff+i);
		memcpy(tmp_iv,dstBuff+i,step);
		dst_len+=step;
	}
	return dst_len;
}

/* iv是初始化向量 */
void zhAesDecryptCBC(char*iv,int iv_len,char *buff,int buffLen)
{
	int i;
	int k;
	char tmp_iv[32];
	char new_iv[32];
	short step;

	step=Nb*4;
	memcpy(tmp_iv,iv,step);
	for(i=0;i<buffLen;i+=step)
	{
		memcpy(new_iv,buff+i,step);
		zhAesDecrypt(buff+i);
		for(k=0;k<step;k++)
		{
			buff[i+k]=buff[i+k]^tmp_iv[k];
		}
		memcpy(tmp_iv,new_iv,step);
	}
}