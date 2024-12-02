#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;
#define MUL2(a) (a<<1)^(a&0x80?0x1b:0)
 /*#define poly_degree(poly) ( \
    ((poly) & 0x80) ? 7 : \
    ((poly) & 0x40) ? 6 : \
    ((poly) & 0x20) ? 5 : \
    ((poly) & 0x10) ? 4 : \
    ((poly) & 0x08) ? 3 : \
    ((poly) & 0x04) ? 2 : \
    ((poly) & 0x02) ? 1 : \
    ((poly) & 0x01) ? 0 : -1 )
*/

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

u8 poly_degree(u32 poly) {
    int deg = -1;
    while(poly) {
        poly >>= 1;
        deg++;
    }
    return deg;
} 


u8 gf_mod(u8 a) {
    while(poly_degree(a) >= 8) {
        int shift = poly_degree(a) - 8;
        a ^= 0x11b << shift;
    }
    return a;
}

u8 eea(u8 a) {
    if (a == 0)
        return 0;

    u32 u = a;
    u32 v = 0x11b;
    u32 g1 = 1;
    u32 g2 = 0;

    for (int i = 0; i < 8; i++) {
        int deg_u = poly_degree(u);
        int deg_v = poly_degree(v);

        if (u == 1)
            break;

        if (deg_u < deg_v) {
            // Swap u and v
            u32 temp_u = u; u = v; v = temp_u;
            // Swap g1 and g2
            u32 temp_g = g1; g1 = g2; g2 = temp_g;
            deg_u = poly_degree(u);
            deg_v = poly_degree(v);
        }

        u8 shift = deg_u - deg_v;

        // u = u + v * x^shift
        u ^= v << shift;
        gf_mod(u);
        // g1 = g1 + g2 * x^shift
        g1 ^= g2 << shift;
        gf_mod(g1);
    }

    return (u8)g1;
}

int main() {
    u8 a = 0x10;
    u8 inv = eea(a);
    printf("inv: 0x%02x -> 0x%02x\n", a, inv);
    printf("chk: 0x%02x * 0x%02x = 0x%02x\n", a, inv, mul(a, inv));
    
}