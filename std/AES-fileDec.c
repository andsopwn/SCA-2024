#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "aes.h"

#define DEBUG 0

void AES_ENC_Optimization(u8 *PT, u8 *CT, u32 *W, int keysize) {
    u32   S0, S1, S2, S3, T0, T1, T2, T3;

    //0 round
    S0 = u4byte_in(PT)        ^ W[0];
    S1 = u4byte_in(PT + 4)    ^ W[1];
    S2 = u4byte_in(PT + 8)    ^ W[2];
    S3 = u4byte_in(PT + 12)   ^ W[3];

    //1 round
    T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[4];
    T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[5];
    T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[6];
    T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[7];

    //2 round
    S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[8];
    S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[9];
    S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[10];
    S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[11];

    //3 round
    T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[12];
    T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[13];
    T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[14];
    T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[15];

    //4 round
    S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[16];
    S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[17];
    S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[18];
    S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[19];

    //5 round
    T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[20];
    T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[21];
    T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[22];
    T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[23];

    //6 round
    S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[24];
    S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[25];
    S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[26];
    S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[27];

    //7 round
    T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[28];
    T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[29];
    T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[30];
    T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[31];

    //8 round
    S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[32];
    S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[33];
    S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[34];
    S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[35];

    //9 round
    T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[36];
    T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[37];
    T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[38];
    T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[39];

    if (keysize == 128) {
        //10 round
        S0 = (Te2[(T0 >> 24)] & 0xff000000) ^ (Te3[(T1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T3 & 0xff] & 0x000000ff) ^ W[40];
        S1 = (Te2[(T1 >> 24)] & 0xff000000) ^ (Te3[(T2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T0 & 0xff] & 0x000000ff) ^ W[41];
        S2 = (Te2[(T2 >> 24)] & 0xff000000) ^ (Te3[(T3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T1 & 0xff] & 0x000000ff) ^ W[42];
        S3 = (Te2[(T3 >> 24)] & 0xff000000) ^ (Te3[(T0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T2 & 0xff] & 0x000000ff) ^ W[43];
        }
    else if (keysize == 192) {
        //10 round
        S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[40];
        S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[41];
        S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[42];
        S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[43];

        //11 round
        T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[44];
        T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[45];
        T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[46];
        T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[47];

        //12 round
        S0 = (Te2[(T0 >> 24)] & 0xff000000) ^ (Te3[(T1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T3 & 0xff] & 0x000000ff) ^ W[48];
        S1 = (Te2[(T1 >> 24)] & 0xff000000) ^ (Te3[(T2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T0 & 0xff] & 0x000000ff) ^ W[49];
        S2 = (Te2[(T2 >> 24)] & 0xff000000) ^ (Te3[(T3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T1 & 0xff] & 0x000000ff) ^ W[50];
        S3 = (Te2[(T3 >> 24)] & 0xff000000) ^ (Te3[(T0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T2 & 0xff] & 0x000000ff) ^ W[51];
    }
    else if (keysize == 256) {
        //10 round
        S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[40];
        S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[41];
        S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[42];
        S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[43];

        //11 round
        T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[44];
        T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[45];
        T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[46];
        T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[47];

        //12 round
        S0 = Te0[T0 >> 24] ^ Te1[(T1 >> 16) & 0xff] ^ Te2[(T2 >> 8) & 0xff] ^ Te3[T3 & 0xff] ^ W[48];
        S1 = Te0[T1 >> 24] ^ Te1[(T2 >> 16) & 0xff] ^ Te2[(T3 >> 8) & 0xff] ^ Te3[T0 & 0xff] ^ W[49];
        S2 = Te0[T2 >> 24] ^ Te1[(T3 >> 16) & 0xff] ^ Te2[(T0 >> 8) & 0xff] ^ Te3[T1 & 0xff] ^ W[50];
        S3 = Te0[T3 >> 24] ^ Te1[(T0 >> 16) & 0xff] ^ Te2[(T1 >> 8) & 0xff] ^ Te3[T2 & 0xff] ^ W[51];

        //13 round
        T0 = Te0[S0 >> 24] ^ Te1[(S1 >> 16) & 0xff] ^ Te2[(S2 >> 8) & 0xff] ^ Te3[S3 & 0xff] ^ W[52];
        T1 = Te0[S1 >> 24] ^ Te1[(S2 >> 16) & 0xff] ^ Te2[(S3 >> 8) & 0xff] ^ Te3[S0 & 0xff] ^ W[53];
        T2 = Te0[S2 >> 24] ^ Te1[(S3 >> 16) & 0xff] ^ Te2[(S0 >> 8) & 0xff] ^ Te3[S1 & 0xff] ^ W[54];
        T3 = Te0[S3 >> 24] ^ Te1[(S0 >> 16) & 0xff] ^ Te2[(S1 >> 8) & 0xff] ^ Te3[S2 & 0xff] ^ W[55];

        //14 round
        S0 = (Te2[(T0 >> 24)] & 0xff000000) ^ (Te3[(T1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T3 & 0xff] & 0x000000ff) ^ W[56];
        S1 = (Te2[(T1 >> 24)] & 0xff000000) ^ (Te3[(T2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T0 & 0xff] & 0x000000ff) ^ W[57];
        S2 = (Te2[(T2 >> 24)] & 0xff000000) ^ (Te3[(T3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T1 & 0xff] & 0x000000ff) ^ W[58];
        S3 = (Te2[(T3 >> 24)] & 0xff000000) ^ (Te3[(T0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(T1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[T2 & 0xff] & 0x000000ff) ^ W[59];
    }
    else { exit(-1); }

    u4byte_out(CT, S0);
    u4byte_out(CT + 4, S1);
    u4byte_out(CT + 8, S2);
    u4byte_out(CT + 12, S3);
}

void AES_DEC_Optimization(u8 *PT, u8 *CT, u32 *W, int keysize) {
    u32   S0, S1, S2, S3, T0, T1, T2, T3;

    if(keysize == 128) {
        S0 = u4byte_in(CT)       ^ W[40];
        S1 = u4byte_in(CT + 4)   ^ W[41];
        S2 = u4byte_in(CT + 8)   ^ W[42];
        S3 = u4byte_in(CT + 12)  ^ W[43];

            //  10 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[36];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[37];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[38];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[39];
    }
    else if(keysize == 192) {
        S0 = u4byte_in(CT)       ^ W[48];
        S1 = u4byte_in(CT + 4)   ^ W[49];
        S2 = u4byte_in(CT + 8)   ^ W[50];
        S3 = u4byte_in(CT + 12)  ^ W[51];

        //  12 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[44];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[45];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[46];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[47];
        //  11 round
        S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[40];
        S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[41];
        S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[42];
        S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[43];
        //  10 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[36];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[37];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[38];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[39];
    }
    else if(keysize == 256) {
        S0 = u4byte_in(CT)       ^ W[56];
        S1 = u4byte_in(CT + 4)   ^ W[57];
        S2 = u4byte_in(CT + 8)   ^ W[58];
        S3 = u4byte_in(CT + 12)  ^ W[59];
        //  14 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[52];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[53];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[54];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[55];
        //  13 round
        S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[48];
        S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[49];
        S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[50];
        S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[51];
        //  12 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[44];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[45];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[46];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[47];
        //  11 round
        S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[40];
        S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[41];
        S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[42];
        S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[43];
        //  10 round
        T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[36];
        T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[37];
        T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[38];
        T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[39];
    }
    else { exit(-1); }
    // 9 round
    S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[32];
    S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[33];
    S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[34];
    S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[35];

    // 8 round
    T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[28];
    T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[29];
    T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[30];
    T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[31];

    // 7 round
    S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[24];
    S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[25];
    S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[26];
    S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[27];

    // 6 round
    T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[20];
    T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[21];
    T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[22];
    T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[23];

    // 5 round
    S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[16];
    S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[17];
    S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[18];
    S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[19];
    // 4 round
    T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[12];
    T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[13];
    T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[14];
    T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[15];
    // 3 round
    S0 = Td0[T0 >> 24] ^ Td3[T1 & 0xff] ^ Td2[(T2 >> 8) & 0xff] ^ Td1[(T3 >> 16) & 0xff] ^ W[8];
    S1 = Td0[T1 >> 24] ^ Td3[T2 & 0xff] ^ Td2[(T3 >> 8) & 0xff] ^ Td1[(T0 >> 16) & 0xff] ^ W[9];
    S2 = Td0[T2 >> 24] ^ Td3[T3 & 0xff] ^ Td2[(T0 >> 8) & 0xff] ^ Td1[(T1 >> 16) & 0xff] ^ W[10];
    S3 = Td0[T3 >> 24] ^ Td3[T0 & 0xff] ^ Td2[(T1 >> 8) & 0xff] ^ Td1[(T2 >> 16) & 0xff] ^ W[11];

    // 2 round
    T0 = Td0[S0 >> 24] ^ Td3[S1 & 0xff] ^ Td2[(S2 >> 8) & 0xff] ^ Td1[(S3 >> 16) & 0xff] ^ W[4];
    T1 = Td0[S1 >> 24] ^ Td3[S2 & 0xff] ^ Td2[(S3 >> 8) & 0xff] ^ Td1[(S0 >> 16) & 0xff] ^ W[5];
    T2 = Td0[S2 >> 24] ^ Td3[S3 & 0xff] ^ Td2[(S0 >> 8) & 0xff] ^ Td1[(S1 >> 16) & 0xff] ^ W[6];
    T3 = Td0[S3 >> 24] ^ Td3[S0 & 0xff] ^ Td2[(S1 >> 8) & 0xff] ^ Td1[(S2 >> 16) & 0xff] ^ W[7];

    // 1 round
    S0 = ((u32)invSbox[T0 >> 24] << 24) ^ ((u32)invSbox[T1 & 0xff]) ^ ((u32)invSbox[(T2 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(T3 >> 16) & 0xff] << 16) ^ W[0];
    S1 = ((u32)invSbox[T1 >> 24] << 24) ^ ((u32)invSbox[T2 & 0xff]) ^ ((u32)invSbox[(T3 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(T0 >> 16) & 0xff] << 16) ^ W[1];
    S2 = ((u32)invSbox[T2 >> 24] << 24) ^ ((u32)invSbox[T3 & 0xff]) ^ ((u32)invSbox[(T0 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(T1 >> 16) & 0xff] << 16) ^ W[2];
    S3 = ((u32)invSbox[T3 >> 24] << 24) ^ ((u32)invSbox[T0 & 0xff]) ^ ((u32)invSbox[(T1 >> 8) & 0xff] << 8) ^ ((u32)invSbox[(T2 >> 16) & 0xff] << 16) ^ W[3];

    u4byte_out(PT, S0);
    u4byte_out(PT + 4, S1);
    u4byte_out(PT + 8, S2);
    u4byte_out(PT + 12, S3);
}

void AES_KeySchedule_Optimization(u8 *MK, int keysize) {
    int   i;
    u32   T[32];
    u32   M[32];
    u8    RK[240];

    if(keysize == 128) {
        for(i = 0 ; i < 4 ; i++)
            W[i] = u4byte_in(MK + i * 4);

        for(i = 0 ; i < 10 ; i++) { 
            W[i * 4 + 4] = W[i * 4] ^ (SubWord(RotWord(W[4 * i + 3]))) ^ Rcons[i];
            W[i * 4 + 5] = W[i * 4 + 1] ^ W[i * 4 + 4];
            W[i * 4 + 6] = W[i * 4 + 2] ^ W[i * 4 + 5];
            W[i * 4 + 7] = W[i * 4 + 3] ^ W[i * 4 + 6];
        }
    }
    else if(keysize == 192) {
        for(i = 0 ; i < 6 ; i++)
            W[i] = u4byte_in(MK + i * 4);

        for(i = 0 ; i < 8 ; i++) { 
            W[6 * i + 6] = W[6 * i] ^ (SubWord(RotWord(W[6 * i + 5]))) ^ Rcons[i];
            W[6 * i + 7] = W[6 * i + 1] ^ W[6 * i + 6];
            W[6 * i + 8] = W[6 * i + 2] ^ W[6 * i + 7];
            W[6 * i + 9] = W[6 * i + 3] ^ W[6 * i + 8];
            W[6 * i + 10] = W[6 * i + 4] ^ W[6 * i + 9];
            W[6 * i + 11] = W[6 * i + 5] ^ W[6 * i + 10];
        }
    }
    else if(keysize == 256) {
        for(i = 0 ; i < 8 ; i++)
            W[i] = u4byte_in(MK + i*4);
        
        for(i = 0 ; i < 7 ; i++) {
            W[8 * i + 8] = W[8 * i] ^ (SubWord(RotWord(W[8 * i + 7]))) ^ Rcons[i];
            W[8 * i + 9] = W[8 * i + 1] ^ W[8 * i + 8];
            W[8 * i + 10] = W[8 * i + 2] ^ W[8 * i + 9];
            W[8 * i + 11] = W[8 * i + 3] ^ W[8 * i + 10];
            if(i == 6) break;
            W[8 * i + 12] = W[8 * i + 4] ^ (SubWord(W[8 * i + 11]));
            W[8 * i + 13] = W[8 * i + 5] ^ W[8 * i + 12];
            W[8 * i + 14] = W[8 * i + 6] ^ W[8 * i + 13];
            W[8 * i + 15] = W[8 * i + 7] ^ W[8 * i + 14];
        }
    }
    else { exit(-1); }

    // Decryption Key Scheduling 
    for(int i = 0 ; i < 60 ; i++) Wd[i] = W[i];
        for(int i = 0 ; i < 60 ; i++) u4byte_out(RK + i * 4, W[i]);
        for(int i = 1 ; i < keysize / 32 + 6 ; i++) { 
            for(int k = 0; k < 16; k += 4) {
            T[k]     = MULE(RK[i * 16 + k]) ^ MULB(RK[i * 16 + k + 1]) ^ MULD(RK[i * 16 + k + 2]) ^ MUL9(RK[i * 16 + k + 3]);
            T[k + 1] = MUL9(RK[i * 16 + k]) ^ MULE(RK[i * 16 + k + 1]) ^ MULB(RK[i * 16 + k + 2]) ^ MULD(RK[i * 16 + k + 3]);
            T[k + 2] = MULD(RK[i * 16 + k]) ^ MUL9(RK[i * 16 + k + 1]) ^ MULE(RK[i * 16 + k + 2]) ^ MULB(RK[i * 16 + k + 3]);
            T[k + 3] = MULB(RK[i * 16 + k]) ^ MULD(RK[i * 16 + k + 1]) ^ MUL9(RK[i * 16 + k + 2]) ^ MULE(RK[i * 16 + k + 3]);
            }
            for(int k = 0 ; k < 16 ; k++) RK[i * 16 + k] = T[k];
        }
        for(int i = 0; i < 60 ; i++)    Wd[i] = u4byte_in(RK + i * 4);
}

clock_t AES_DEC_MODE(char* inst, char* outst, u32 *W, int keysize, char *mode) {
    u32      fileSize;         // 파일의 크기를 담을 변수입니다.
    u8       Padding     = 0;  // 패딩 값입니다.
    u8       *encryptedFile;   // 파일의 바이너리 값을 올리기 위한 변수입니다.
    u8       *decryptedFile;   // 복호화된 파일 
    FILE     *RFP, * WFP;      // RFP - read, WFP - Write 파일 입출력
    clock_t  start = 0, finish = 0;
    u32      time = 0;

    if((RFP = fopen(inst, "rb")) == NULL) { puts("파일 스트림 읽기 에러"); return 0; }

    fseek(RFP, 0, SEEK_END);   // 파일크기 읽기
    fileSize = ftell(RFP);    

    fseek(RFP, 0, SEEK_SET); 
    encryptedFile = calloc(fileSize, sizeof(u8)); 
    decryptedFile = calloc(fileSize, sizeof(u8)); 

    fread(encryptedFile, 1, fileSize, RFP);
    fclose(RFP);

    if((WFP = fopen(outst, "wb")) == NULL) { puts("파일 스트림 쓰기 에러"); return 0; }

    if((strncmp(mode, "CTR", 3) == 0) || (strncmp(mode, "ctr", 3) == 0)) {
        u8  CTR[16] = { 0x00, };
        puts("CTR");

        for(int i = 0 ; i < (int)(fileSize / 16) ; i++) {
            CTR[15] = i & 0xff;
            CTR[14] = (i >> 8) & 0xff;
            CTR[13] = (i >> 16) & 0xff;
            CTR[12] = (i >> 24) & 0xff;
            start = clock();
            AES_ENC_Optimization(CTR, decryptedFile + i * 16, W, keysize);
            finish = clock();
            time += (double)(finish - start);
            for(int j = 0 ; j < 16 ; j++) 
                decryptedFile[i * 16 + j] ^= encryptedFile[i * 16 + j];
        }
    }
    else if((strncmp(mode, "ECB", 3) == 0) || (strncmp(mode, "ecb", 3) == 0)) {
        puts("ECB");
        for(int i = 0 ; i < (int)(fileSize / 16) ; i++) {
            start = clock();
            AES_DEC_Optimization(decryptedFile + i * 16, encryptedFile + i * 16, Wd, keysize);
            finish = clock();
            time += (double)(finish - start);
        }
    }
    else if((strncmp(mode, "CBC", 3) == 0) || (strncmp(mode, "cbc", 3) == 0)) {
        u8  iv[16] = { 0x00, };
        puts("CBC");
        for(int i = 0 ; i < (int)(fileSize / 16) ; i++) {
            start = clock();
            AES_DEC_Optimization(decryptedFile + i * 16, encryptedFile + i * 16, Wd, keysize);
            finish = clock();
            time += (double)(finish - start);
            if(i != 0) {
            for(int j = 0 ; j < 16 ; j++)
                decryptedFile[i * 16 + j] ^= encryptedFile[(i-1) * 16 + j];
            }
            else {
                for(int j = 0 ; j < 16 ; j++)
                    decryptedFile[i * 16 + j] ^= iv[j];
            }
        }
    }

    
    // 패딩 검증 및 파일 출력
    Padding = decryptedFile[fileSize - 1]; // 임의로 맨 마지막 한 바이트를 패딩으로 설정한다
    if(Padding > 0x10)   Padding = 0;      // 패딩 예외처리
    fwrite(decryptedFile, sizeof(u8), fileSize - decryptedFile[fileSize - 1], WFP); // 파일 사이즈에서 패딩 값 뺸 만큼 파일출력
    fclose(WFP);

    printf("[%d Blocks]\n", (int)(fileSize / 16));
    free(encryptedFile);
    free(decryptedFile);

    return time;
}

int main(int argc, char* argv[]) {

    u8       MK[32]      = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    int      keysize     = 128;
    int      mode = 0;
    clock_t  start = 0, finish = 0, time = 0;


    if(argc != 4) { puts("Usage : ./Dec {Encrypted File} {New FileName} {Mode}"); return 0; }

    AES_KeySchedule_Optimization(MK, keysize);
    time = AES_DEC_MODE(argv[1], argv[2], W, keysize, argv[3]);

    printf("원본 파일\t%s\n해독 파일\t%s\n운영 모드\t%s\n연산 시간\t%f초\n", argv[1], argv[2], argv[3], (double)time / CLOCKS_PER_SEC);

    return 0;
}