#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t data[4];  // data[0]: 하위 32비트, data[3]: 상위 32비트
} uint128_t;

void uint128_init(uint128_t *num, uint32_t value) {
    num->data[0] = value;
    num->data[1] = 0;
    num->data[2] = 0;
    num->data[3] = 0;
}

void uint128_copy(uint128_t *dest, const uint128_t *src) {
    memcpy(dest->data, src->data, sizeof(uint32_t) * 4);
}

void uint128_print(const uint128_t *num) {
    printf("0x%08X%08X%08X%08X",
           num->data[3], num->data[2], num->data[1], num->data[0]);
}

void gf2_128_add(uint128_t *result, const uint128_t *a, const uint128_t *b) {
    for (int i = 0; i < 4; i++) {
        result->data[i] = a->data[i] ^ b->data[i];
    }
}

// GF(2^128)에서의 곱셈
void gf2_128_mul(uint128_t *result, const uint128_t *a, const uint128_t *b) {
    uint128_t temp = {{0, 0, 0, 0}};
    uint128_t a_copy;
    uint128_copy(&a_copy, a);

    for (int i = 127; i >= 0; i--) {
        if ((b->data[i / 32] >> (i % 32)) & 1) {
            gf2_128_add(&temp, &temp, &a_copy);
        }

        // 다음 비트를 위해 a_copy를 좌측으로 시프트하고 필요하면 모듈러 감소
        uint32_t carry = a_copy.data[3] >> 31;
        for (int j = 3; j > 0; j--) {
            a_copy.data[j] = (a_copy.data[j] << 1) | (a_copy.data[j - 1] >> 31);
        }
        a_copy.data[0] <<= 1;

        if (carry) {
            // 불가약 다항식: x^128 + x^7 + x^2 + x + 1 (16진수로 0x87)
            // 상위 비트가 넘어갔을 때 불가약 다항식을 XOR하여 모듈러 연산 수행
            a_copy.data[0] ^= 0x87;
        }
    }

    uint128_copy(result, &temp);
}

// Left-to-Right 이진 지수승 알고리즘
void gf2_128_exp(uint128_t *result, const uint128_t *g, const uint128_t *e) {
    uint128_t A;
    uint128_init(&A, 1);  // A ← 1

    // 지수 e의 비트 길이 계산 (최상위 비트 위치 찾기)
    int t = 127;
    while (t >= 0) {
        if ((e->data[t / 32] >> (t % 32)) & 1) {
            break;
        }
        t--;
    }

    // 알고리즘 수행
    for (int i = t; i >= 0; i--) {
        // A ← A · A
        gf2_128_mul(&A, &A, &A);

        // 만약 e_i == 1이면 A ← A · g
        if ((e->data[i / 32] >> (i % 32)) & 1) {
            gf2_128_mul(&A, &A, g);
        }
    }

    uint128_copy(result, &A);
}

int main() {
    uint128_t g = {{0x89ABCDEF, 0x01234567, 0x89ABCDEF, 0x01234567}};
    uint128_t e = {{0xFEDCBA98, 0x76543210, 0xFEDCBA98, 0x76543210}};
    uint128_t result;

    gf2_128_exp(&result, &g, &e);

    printf("Result: ");
    uint128_print(&result);
    printf("\n");

    return 0;
}
