#include <stdint.h>
#include <stdio.h>

typedef unsigned char u8;

// GF(2^8)에서의 곱셈 매크로 정의
#define MUL2(a) ((a << 1) ^ ((a & 0x80) ? 0x1b : 0))
#define MUL3(a) (MUL2(a) ^ (a))
#define MUL4(a) (MUL2(MUL2(a)))
#define MUL8(a) (MUL2(MUL2(MUL2(a))))
#define MUL9(a) (MUL8(a) ^ (a))
#define MULB(a) (MUL8(a) ^ MUL2(a) ^ (a))
#define MULD(a) (MUL8(a) ^ MUL4(a) ^ (a))
#define MULE(a) (MUL8(a) ^ MUL4(a) ^ MUL2(a))

u8 mul(u8 a, u8 b) {
	u8 c = 0;
	c ^= (a & 0x01) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x02) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x04) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x08) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x10) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x20) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x40) ? b : 0;
	b = MUL2(b);
	c ^= (a & 0x80) ? b : 0;
	return c;
}

static const u8 gf16_inv_table[16] = {
        0, 1, 9, 0xE, 0xB, 0xD, 7, 6, 0xF, 2, 0xC, 4, 0xA, 5, 3, 8
};

u8 gf16_mul(u8 a, u8 b) {
    u8 c = 0;
    while (a) {
        if (a & 1) 
        c ^= b;     a >>= 1;    b <<= 1;
        if (b & 0x10) 
        b ^= 0x13;    b &= 0x0F;
    }
    return c;
}

// P^-1 계산 함수
u8 compute_inverse(u8 P) {
    u8 Ph = P >> 4;
    u8 Pl = P & 0x0F;

    u8 Ph2 = gf16_mul(Ph, Ph);
    u8 Pl2 = gf16_mul(Pl, Pl);
    u8 PhPl = gf16_mul(Ph, Pl);

    u8 Rh = gf16_mul(gf16_inv_table[Ph2 ^ PhPl ^ Pl2], Ph);
    u8 Rl = gf16_mul(gf16_inv_table[Ph2 ^ PhPl ^ Pl2], Ph ^ Pl);

    u8 P_inv = (Rh << 4) | Rl;

    return P_inv;
}

int main() {
    u8 P = 0x49;
    u8 P_inv = compute_inverse(P);
    printf("P = 0x%02X\n", P);
    printf("P^-1 = 0x%02X\n", P_inv);

    u8 check = mul(P, P_inv);
    printf("P * P^-1 = 0x%02X\n", check);
    return 0;
}
