#include <stdio.h>
#include <stdlib.h>
typedef unsigned char u8;
typedef unsigned int u32;
#define MUL2(a) (a<<1)^(a&0x80?0x1b:0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

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

u8 inv(u8 a) {
	u8 r;
	r = a;
	r = mul(r, r); // a^2
	r = mul(r, a); // a^3
	r = mul(r, r); // a^6
	r = mul(r, a); // a^7
	r = mul(r, r); // a^14
	r = mul(r, a); // a^15
	r = mul(r, r); // a^30
	r = mul(r, a); // a^31
	r = mul(r, r); // a^62
	r = mul(r, a); // a^63
	r = mul(r, r); // a^126
	r = mul(r, a); // a^127
	r = mul(r, r); // a^254
	return r;
}

u8 GenSbox(u8 a) {
	u8 r, temp;
	temp = inv(a);
	r = 0;
	if (temp & 0x01) r ^= 0x1f;
	if (temp & 0x02) r ^= 0x3e;
	if (temp & 0x04) r ^= 0x7c;
	if (temp & 0x08) r ^= 0xf8;
	if (temp & 0x10) r ^= 0xf1;
	if (temp & 0x20) r ^= 0xe3;
	if (temp & 0x40) r ^= 0xc7;
	if (temp & 0x80) r ^= 0x8f;
	r ^= 0x63;
	return r;
}

int main() {
	/*
    for(int i = 0 ; i <= 0xff ; i++) {
        printf("%02X ", GenSbox(i));
        if(i % 16 == 15) puts("");
    }
	*/
	u8 a = 0x56;
	a = inv(a);
	printf("inv -> 0x%02x\n", a);
}