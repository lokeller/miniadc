/*
 *
 * Tiger: A Fast New Hash Function
 * Ross Anderson and Eli Biham
 *
 * http://www.cs.technion.ac.il/~biham/Reports/Tiger/
 *
 * Tiger has no usage restrictions nor patents. It can be used freely,
 * with the reference implementation, with other implementations or with
 * a modification to the reference implementation (as long as it still
 * implements Tiger). We only ask you to let us know about your
 * implementation and to cite the origin of Tiger and of the reference
 * implementation.
 *
 *
 */

#include "tiger.h"

typedef uint64_t word64;
typedef uint32_t word32;
typedef uint8_t byte;


/* for Alpha is required. It is used only for          */
/* optimization of time. Otherwise it does nothing.    */
#ifdef __alpha
#define OPTIMIZE_FOR_ALPHA
#endif

/* NOTE that this code is NOT FULLY OPTIMIZED for any  */
/* machine. Assembly code might be much faster on some */
/* machines, especially if the code is compiled with   */
/* gcc.                                                */

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3

extern word64 table[4*256];

#define t1 (table)
#define t2 (table+256)
#define t3 (table+256*2)
#define t4 (table+256*3)

#define round(a,b,c,x,mul) \
      c ^= x; \
      a -= t1[(byte)(c)] ^ \
           t2[(byte)(((word32)(c))>>(2*8))] ^ \
	   t3[(byte)((c)>>(4*8))] ^ \
           t4[(byte)(((word32)((c)>>(4*8)))>>(2*8))] ; \
      b += t4[(byte)(((word32)(c))>>(1*8))] ^ \
           t3[(byte)(((word32)(c))>>(3*8))] ^ \
	   t2[(byte)(((word32)((c)>>(4*8)))>>(1*8))] ^ \
           t1[(byte)(((word32)((c)>>(4*8)))>>(3*8))]; \
      b *= mul;

#define pass(a,b,c,mul) \
      round(a,b,c,x0,mul) \
      round(b,c,a,x1,mul) \
      round(c,a,b,x2,mul) \
      round(a,b,c,x3,mul) \
      round(b,c,a,x4,mul) \
      round(c,a,b,x5,mul) \
      round(a,b,c,x6,mul) \
      round(b,c,a,x7,mul)

/* The compress function is a function. Requires smaller cache?    */
void tiger_compress(word64 *str, word64 state[3])
{
  register word64 a, b, c, tmpa; 
  word64 aa, bb, cc; 
  register word64 x0, x1, x2, x3, x4, x5, x6, x7;
  int pass_no; 

  a = state[0]; 
  b = state[1];
  c = state[2];

  x0=str[0]; x1=str[1]; x2=str[2]; x3=str[3]; 
  x4=str[4]; x5=str[5]; x6=str[6]; x7=str[7];

  /* save abc */
  aa = a;
  bb = b;
  cc = c;
  
  for(pass_no=0; pass_no<PASSES; pass_no++) {
    if(pass_no != 0) {
      /* key schedule */
      x0 -= x7 ^ 0xA5A5A5A5A5A5A5A5LL; 
      x1 ^= x0; 
      x2 += x1;
      x3 -= x2 ^ ((~x1)<<19);
      x4 ^= x3;
      x5 += x4;
      x6 -= x5 ^ ((~x4)>>23);
      x7 ^= x6;
      x0 += x7;
      x1 -= x0 ^ ((~x7)<<19);
      x2 ^= x1;
      x3 += x2;
      x4 -= x3 ^ ((~x2)>>23);
      x5 ^= x4;
      x6 += x5;
      x7 -= x6 ^ 0x0123456789ABCDEFLL;
    }
    pass(a,b,c,(pass_no==0?5:pass_no==1?7:9));
    tmpa=a;
    a=c;
    c=b;
    b=tmpa;
  } 
  
  /* feedforward */

  a ^= aa;
  b -= bb; 
  c += cc;

  state[0] = a; 
  state[1] = b; 
  state[2] = c; 
}

void tiger(word64 *str, word64 length, word64 res[3])
{
  register word64 i, j;
  unsigned char temp[64];

  res[0]=0x0123456789ABCDEFLL;
  res[1]=0xFEDCBA9876543210LL;
  res[2]=0xF096A5B4C3B2E187LL;

  for(i=length; i>=64; i-=64)
    {
      tiger_compress(str, res);
      str += 8;
    }

  for(j=0; j<i; j++)
    temp[j] = ((byte*)str)[j];

  temp[j++] = 0x01;
  for(; j&7; j++)
    temp[j] = 0;
  if(j>56)
    {
      for(; j<64; j++)
	temp[j] = 0;
      tiger_compress(((word64*)temp), res);
      j=0;
    }

  for(; j<56; j++)
    temp[j] = 0;
  ((word64*)(&(temp[56])))[0] = ((word64)length)<<3;
  tiger_compress(((word64*)temp), res);
}
