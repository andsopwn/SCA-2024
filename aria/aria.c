#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned char u8;

u8 MS[4][256] = { 0x00, };
const u8    S[4][256] = {
    // Sbox Type 1
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    },
    // Sbox Type 2
    {
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
    },
    // Inverse Sbox Type 1
    {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    },
    // Inverse Sbox Type 2
    {
    0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
    0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
    0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
    0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
    0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
    0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
    0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
    0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
    0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
    0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
    0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
    0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
    0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
    0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
    0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
    0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60
    }
};
const u8    KRK[3][16] = {
    { 
        0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0
    }, 
    
    {
        0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0
    }, 
    
    {
        0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e
    }
};

void prt(u8 *S) { for(int i = 0 ; i < 16 ; i++) printf("%02X ", S[i]); puts(""); }

static inline void DiffLayer(const u8 *IN, u8 *OUT) {
    register u8 x0 = IN[0];
    register u8 x1 = IN[1];
    register u8 x2 = IN[2];
    register u8 x3 = IN[3];
    register u8 x4 = IN[4];
    register u8 x5 = IN[5];
    register u8 x6 = IN[6];
    register u8 x7 = IN[7];
    register u8 x8 = IN[8];
    register u8 x9 = IN[9];
    register u8 x10 = IN[10];
    register u8 x11 = IN[11];
    register u8 x12 = IN[12];
    register u8 x13 = IN[13];
    register u8 x14 = IN[14];
    register u8 x15 = IN[15];
    
    register u8 T1 = x3 ^ x4 ^ x9 ^ x14;
    register u8 T2 = x2 ^ x5 ^ x8 ^ x15;
    register u8 T3 = x1 ^ x6 ^ x11 ^ x12;
    register u8 T4 = x0 ^ x7 ^ x10 ^ x13;

    OUT[0]  = x6 ^ x8 ^ x13 ^ T1;
    OUT[1]  = x7 ^ x9 ^ x12 ^ T2;
    OUT[2]  = x4 ^ x10 ^ x15 ^ T3;
    OUT[3]  = x5 ^ x11 ^ x14 ^ T4;
    OUT[4]  = x0 ^ x11 ^ x14 ^ T2;
    OUT[5]  = x1 ^ x10 ^ x15 ^ T1;
    OUT[6]  = x2 ^ x9 ^ x12 ^ T4;
    OUT[7]  = x3 ^ x8 ^ x13 ^ T3;
    OUT[8]  = x1 ^ x4 ^ x15 ^ T4;
    OUT[9]  = x0 ^ x5 ^ x14 ^ T3;
    OUT[10] = x3 ^ x6 ^ x13 ^ T2;
    OUT[11] = x2 ^ x7 ^ x12 ^ T1;
    OUT[12] = x2 ^ x7 ^ x9  ^ T3;
    OUT[13] = x3 ^ x6 ^ x8  ^ T4;
    OUT[14] = x0 ^ x5 ^ x11 ^ T1;
    OUT[15] = x1 ^ x4 ^ x10 ^ T2;
}

static inline void RotateXOR(const u8 *IN, int n, u8 *OUT) {
    int q = n / 8;
    n %= 8;
    for(int i = 0 ; i < 16 ; i++) {
        OUT[(q + i) % 16] ^= (IN[i] >> n);
        if(n != 0) 
            OUT[(q + i + 1) % 16] ^= (IN[i] << (8 - n));
    }
}

int ENC_KeySchedule(const u8 *MK, u8 *RK, int keysize) {
    int     R = (keysize + 256) / 32; 
    int     q = (keysize - 128) / 64;
    int     i;
    u8      T[16];
    u8      W1[16];
    u8      W2[16];
    u8      W3[16];
    
	for(i = 0 ; i < 16 ; i++)   
        T[i] = S[i % 4][KRK[q][i] ^ MK[i]];
    DiffLayer(T, W1);

	if(R == 14)
        for(i = 0 ; i < 8; i++) W1[i] ^= MK[i + 16];
	else if(R == 16) 
        for (i = 0; i < 16; i++) W1[i] ^= MK[i + 16];
    
	q = (q == 2) ? 0 : (q + 1);

	for(i = 0 ; i < 16 ; i++) 
        T[i] = S[(2 + i) % 4][KRK[q][i] ^ W1[i]];
	DiffLayer(T, W2);
	
    for(i = 0 ; i < 16 ; i++)
        W2[i] ^= MK[i];
  
	q = (q == 2) ? 0 : (q + 1);
	for(i = 0 ; i < 16 ; i++)
        T[i] = S[i  % 4][KRK[q][i] ^ W2[i]];
	DiffLayer(T, W3);

	for(i = 0 ; i < 16 ; i++) W3[i] ^= W1[i];
  
	for(i = 0 ; i < 16 * (R + 1) ; i++) RK[i] = 0;
	RotateXOR(MK, 0, RK      ); RotateXOR(W1,  19, RK      );
	RotateXOR(W1, 0, RK +  16); RotateXOR(W2,  19, RK +  16);
	RotateXOR(W2, 0, RK +  32); RotateXOR(W3,  19, RK +  32);
	RotateXOR(W3, 0, RK +  48); RotateXOR(MK,  19, RK +  48);
	RotateXOR(MK, 0, RK +  64); RotateXOR(W1,  31, RK +  64);
	RotateXOR(W1, 0, RK +  80); RotateXOR(W2,  31, RK +  80);
	RotateXOR(W2, 0, RK +  96); RotateXOR(W3,  31, RK +  96);
	RotateXOR(W3, 0, RK + 112); RotateXOR(MK,  31, RK + 112);
	RotateXOR(MK, 0, RK + 128); RotateXOR(W1,  67, RK + 128);
	RotateXOR(W1, 0, RK + 144); RotateXOR(W2,  67, RK + 144);
	RotateXOR(W2, 0, RK + 160); RotateXOR(W3,  67, RK + 160);
	RotateXOR(W3, 0, RK + 176); RotateXOR(MK,  67, RK + 176);
	RotateXOR(MK, 0, RK + 192); RotateXOR(W1,  97, RK + 192);
	if (R > 12) {
		RotateXOR(W1, 0, RK + 208); RotateXOR(W2,  97, RK + 208);
		RotateXOR(W2, 0, RK + 224); RotateXOR(W3,  97, RK + 224);
	}
	if (R > 14) {
		RotateXOR(W3, 0, RK + 240); RotateXOR(MK,  97, RK + 240);
		RotateXOR(MK, 0, RK + 256); RotateXOR(W1, 109, RK + 256);
	}
	return R;
}

int DEC_KeySchedule(const u8 *MK, u8 *RK, int keysize) {
	u8      T[16];
    int     R;
	int     i, j;
  
	R = ENC_KeySchedule(MK, RK, keysize);

	for (j = 0 ; j < 16 ; j++)
    {
		T[j] = RK[j];
		RK[j] = RK[R * 16 + j];
		RK[R * 16 + j] = T[j];
	}
	for (i = 1 ; i <=  R / 2 ; i++){
	    DiffLayer(RK + i * 16, T);
		DiffLayer(RK + (R - i) * 16, RK + i * 16);
		for(j = 0 ; j < 16 ; j++) RK[(R - i) * 16 + j] = T[j];
	}
	return R;
}

void Crypto(const u8 *PT, int R, const u8 *RK, u8 *CT) {
	u8      T[16];
	int     i, j;
  
	for(j = 0 ; j < 16 ; j++) CT[j] = PT[j];
    
	for(i = 0 ; i < R / 2 ; i++) // ENC_KeySchedule(MK, RK, 192) -> 14;
	{
		for (j = 0; j < 16; j++) 
        T[j] = S[j % 4][RK[j] ^ CT[j]]; // S-Box Layer Type 1 
		DiffLayer(T, CT); RK += 16;     // Diffusion Layer
        
		for (j = 0; j < 16; j++)
        T[j] = S[(2 + j) % 4][RK[j] ^ CT[j]];   // S-Box Layer Type 2
		DiffLayer(T, CT); RK += 16;     // Diffusion Layer
        
	}   
	DiffLayer(CT, T);
	for(j = 0; j < 16; j++) CT[j] = RK[j] ^ T[j];
}

int main() {
    int     i;
    u8          RK[272] = { 0x00, }; // RoundKey 16 * 17
    u8          MK[32] = { 0x54, 0x9D, 0x0A, 0x29, 0xD0, 0x0B, 0xC8, 0x0B, 0xDA, 0x7B, 0x19, 0xDD, 0xDF, 0x36, 0x94, 0xB5 };
    u8          PT[16] = { 0xDB, 0x3C, 0x31, 0xD7, 0x3A, 0x54, 0x9D, 0x66, 0x90, 0x4A, 0xF5, 0x2A, 0x0B, 0x5F, 0x43, 0xD9 };
    u8          CT[16] = { 0x00, };
    u8          ek1[16] = { 0xCB, 0xF6 , 0xD7, 0x4C, 0x0B, 0x78, 0xB9, 0x30, 0x22, 0xB4, 0x7E, 0xAA, 0x06, 0xE7, 0x01, 0x2A };
    u8          ek13[16] = { 0x9F, 0x6B, 0xDD, 0x65, 0xDB, 0x73, 0x71, 0x3B, 0xF8, 0xCF, 0x67, 0x77, 0xD9, 0xD1, 0x95, 0x9F };
    u8          P[16] = { 0x00, };
    u8          W1[16] = { 0x00, };
    u8          W2[16] = { 0x12, 0x27, 0x66, 0x34, 0x21, 0x1F, 0x1A, 0x63, 0x0C, 0x60, 0x00, 0x31, 0x1C, 0x31, 0x3C, 0x01 };

    const u8    h0[16] = { 0xED, 0xD8, 0x99, 0xCB, 0xDE, 0xE0, 0xE5, 0x9C, 0xF3, 0x9F, 0xFF, 0xCC, 0xE3, 0xCE, 0xC3, 0xFE };
    const u8    h1[16] = { 0xB8, 0x8D, 0xCC, 0x9E, 0x8B, 0xB5, 0xB0, 0xC9, 0xA6, 0xCA, 0xAA, 0x9B, 0xB6, 0x9B, 0x96, 0xAB };
    const u8    h2[16] = { 0x12, 0x27, 0x66, 0x34, 0x21, 0x1F, 0x1A, 0x63, 0x0C, 0x60, 0x00, 0x31, 0x1C, 0x31, 0x3C, 0x01 };
    const u8    h3[16] = { 0x47, 0x72, 0x33, 0x61, 0x74, 0x4A, 0x4F, 0x36, 0x59, 0x35, 0x55, 0x64, 0x49, 0x64, 0x69, 0x54 };
    u8          s0[16] = { 0xED, 0xD8, 0x99, 0xCB, 0xDE, 0xE0, 0xE5, 0x9C, 0xF3, 0x9F, 0xFF, 0xCC, 0xE3, 0xCE, 0xC3, 0xFE };
    u8          s1[16] = { 0xB8, 0x8D, 0xCC, 0x9E, 0x8B, 0xB5, 0xB0, 0xC9, 0xA6, 0xCA, 0xAA, 0x9B, 0xB6, 0x9B, 0x96, 0xAB };
    u8          s2[16] = { 0x12, 0x27, 0x66, 0x34, 0x21, 0x1F, 0x1A, 0x63, 0x0C, 0x60, 0x00, 0x31, 0x1C, 0x31, 0x3C, 0x01 };
    u8          s3[16] = { 0x47, 0x72, 0x33, 0x61, 0x74, 0x4A, 0x4F, 0x36, 0x59, 0x35, 0x55, 0x64, 0x49, 0x64, 0x69, 0x54 };
    
    Crypto(PT, ENC_KeySchedule(h3, RK, 128), RK, CT);
    puts("평문"); prt(PT);
    puts("암호화"); prt(CT);
    puts("83 9B 66 90 84 D3 D9 53 56 49 1B 0E 62 5F 0C CB <- MUST");
}

/*
    EncryPTion Test Vector
    1 round : 71 f2 58 e5 33 a1 25 79 48 29 48 8f 65 5d 8f f6 
    2 round : d5 b0 6a 76 fb 8b 55 96 3f c4 4b 2f 03 f0 70 4d 
    3 round : 8d 40 db a4 e1 86 bb 7b bf d9 c1 57 04 4b 24 74 
    4 round : 6c 07 61 05 c3 1e 92 ac ab 19 8d 71 59 a3 04 6c 
    5 round : ae 5c 56 34 83 ff 97 9e be e0 78 c6 94 3d 7f e8 
    6 round : 83 4c bc 0e 00 c0 5e 66 d4 04 36 19 f6 6c 61 71 
    7 round : 4f 6b f4 a8 2a 33 7b 1d e1 fb 5d 56 7b f7 01 42 
    8 round : b8 34 ab 22 69 87 b9 99 f4 dc ba 5d 24 a5 c3 37 
    9 round : 48 c9 b1 56 b1 f1 8d 37 73 19 57 f5 11 e9 c9 7b
    10 round : 18 c0 6a 98 d0 d5 e3 4a 9f 63 a2 94 39 56 1c 6f 
    11 round : 4f f0 7f d1 78 83 28 84 29 3a 5f 91 5f f6 34 bb 
    12 round : c6 ec d0 8e 22 c3 0a bd b2 15 cf 74 e2 07 5e 6e
*/