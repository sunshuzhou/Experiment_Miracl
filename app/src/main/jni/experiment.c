//
// Created by 孙书洲 on 15/11/17.
//

#include <jni.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "miracl/miracl.h"
#include "src/hmac_sha1.h"

char bChar[] = "730750818665451459101842416358141509827966381903";
char pChar[] = "1461501637330902918203684832716283019655932542983";
char nChar[] = "1461501637330902918203683121663422642150372888183";
char gxChar[] = "1012746360306660395378213658174943965595577675415";
char gyChar[] = "75650897218223448951292550565147513994140144567";
char hxChar[] = "224936487907180308547085034490832824824803093939";
char hyChar[] = "543652889493671517302050399526044299167343581063";
big ECC_N;
epoint *ECC_G, *ECC_H;

JNIEXPORT jint JNICALL
Java_com_sunshuzhou_experiment_1miracl_MainActivity_valueFromJNI (JNIEnv* env,
                                                                jobject thiz ) {

}

void envirment_init() {
    big a, b, p, x, y;

#if MIRACL==16
    #ifdef MR_FLASH
        miracl *mip = mirsys(500,10);    /* initialise system to base 10, 500 digits per "big" */
    #else
        miracl *mip = mirsys(5000,10);   /* bigger numbers possible if no flash arithmetic     */
    #endif
#else
    miracl *mip = mirsys(5000,10);  /* 5000 digits per "big" */
#endif
    // init
    a = mirvar(-3);
    b = mirvar(0);
    ECC_N = mirvar(0);
    p = mirvar(0);
    x = mirvar(0);
    y = mirvar(0);
    ECC_G = epoint_init();
    ECC_H = epoint_init();

    mip->IOBASE = 10;
    // init curve
    cinstr(b, bChar);
    cinstr(ECC_N, nChar);
    cinstr(p, pChar);
    ecurve_init(a, b, p, MR_PROJECTIVE);

    // init point:  G, H
    cinstr(x, gxChar);
    cinstr(y, gyChar);
    epoint_set(x, y, 0, ECC_G);
    cinstr(x, hxChar);
    cinstr(y, hyChar);
    epoint_set(x, y, 0, ECC_H);
    mip->IOBASE = 16;
    mirkill(a);
    mirkill(b);
    mirkill(p);
    mirkill(x);
    mirkill(y);
}
void envirment_clear() {
    mirkill(ECC_N);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sunshuzhou_experiment_1miracl_Verify_computeForServer(JNIEnv *env, jobject instance,
                                                               jstring ux_, jstring uy_,
                                                               jstring u1x_, jstring u1y_,
                                                               jstring wx_, jstring wy_,
                                                               jstring com1x_, jstring com1y_,
                                                               jstring N1_, jstring sid_,
                                                               jstring alpha_, jstring beta_,
                                                               jstring zeta_) {
    const char *ux = (*env)->GetStringUTFChars(env, ux_, 0);
    const char *uy = (*env)->GetStringUTFChars(env, uy_, 0);
    const char *u1x = (*env)->GetStringUTFChars(env, u1x_, 0);
    const char *u1y = (*env)->GetStringUTFChars(env, u1y_, 0);
    const char *wx = (*env)->GetStringUTFChars(env, wx_, 0);
    const char *wy = (*env)->GetStringUTFChars(env, wy_, 0);
    const char *com1x = (*env)->GetStringUTFChars(env, com1x_, 0);
    const char *com1y = (*env)->GetStringUTFChars(env, com1y_, 0);
    const char *N1 = (*env)->GetStringUTFChars(env, N1_, 0);
    const char *sid = (*env)->GetStringUTFChars(env, sid_, 0);
    const char *alpha = (*env)->GetStringUTFChars(env, alpha_, 0);
    const char *beta = (*env)->GetStringUTFChars(env, beta_, 0);
    const char *zeta = (*env)->GetStringUTFChars(env, zeta_, 0);

    big x, y, d, k1, N2, sum, big1;
    epoint *u, *u1, *w, *com1, *w1, *epoint1, *com, *K;
    int message_len, i;
    unsigned char key[300], tag[SHA1_HASH_SIZE], hexdigest[SHA1_HASH_SIZE * 2 + 1], message[1000], tempChars[300];
    jclass jclass1 = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result;

    envirment_init();
    x = mirvar(0);
    y = mirvar(0);
    d = mirvar(0);
    k1 = mirvar(0);
    N2 = mirvar(0);
    sum = mirvar(0);
    big1 = mirvar(0);
    u = epoint_init();
    u1 = epoint_init();
    w = epoint_init();
    com1 = epoint_init();
    w1 = epoint_init();
    epoint1 = epoint_init();
    com = epoint_init();
    K = epoint_init();

    cinstr(x, ux);
    cinstr(y, uy);
    epoint_set(x, y, 0, u);
    cinstr(x, u1x);
    cinstr(y, u1y);
    epoint_set(x, y, 0, u1);
    cinstr(x, wx);
    cinstr(y, wy);
    epoint_set(x, y, 0, w);
    cinstr(x, com1x);
    cinstr(y, com1y);
    epoint_set(x, y, 0, com1);

    irand((long)time(0));
    bigrand(ECC_N, d);
    bigrand(ECC_N, k1);
    bigbits(80, N2);


    // sum = alpha + beta + zeta
    cinstr(big1, alpha);
    cinstr(sum, beta);
    add(big1, sum, sum);
    cinstr(big1, zeta);
    add(big1, sum, sum);

    // w1 = k1 * H
    ecurve_mult(k1, ECC_H, w1);

    // com = (alpha + beta + zeta) * u + d * H
    ecurve_mult(sum, u, com);
    ecurve_mult(d, ECC_H, epoint1);
    ecurve_add(epoint1, com);

    // K = d * w + k1 * (com1 - sum * u1)
    ecurve_mult(d, w, K);
    ecurve_mult(sum, u1, epoint1);
    ecurve_sub(epoint1, com1);
    ecurve_mult(k1, com1, com1);
    ecurve_add(com1, K);


    // K.y as key
    epoint_get(K, x, y);
    cotstr(y, key);
    // message: u.y || u1.y || w.y || com1.y || N1 || sid
    epoint_get(u, x, y);
    cotstr(y, message);
    message_len = strlen(message);
    epoint_get(u1, x, y);
    cotstr(y, &message[message_len]);
    message_len = strlen(message);
    epoint_get(w, x, y);
    cotstr(y, &message[message_len]);
    message_len = strlen(message);
    epoint_get(com1, x, y);
    cotstr(x, &message[message_len]);
    message_len = strlen(message);
    strcpy(&message[message_len], N1);
    message_len = strlen(message);
    strcpy(&message[message_len], sid);
    message_len = strlen(message);

    hmac_sha1(key, strlen(key), message, message_len, tag, SHA1_HASH_SIZE);

    for (i = 0; i < SHA1_HASH_SIZE; ++i) {
        sprintf(&hexdigest[i * 2], "%02x", tag[i]);
    }
    hexdigest[40] = '\0';

    (*env)->ReleaseStringUTFChars(env, ux_, ux);
    (*env)->ReleaseStringUTFChars(env, uy_, uy);
    (*env)->ReleaseStringUTFChars(env, u1x_, u1x);
    (*env)->ReleaseStringUTFChars(env, u1y_, u1y);
    (*env)->ReleaseStringUTFChars(env, wx_, wx);
    (*env)->ReleaseStringUTFChars(env, wy_, wy);
    (*env)->ReleaseStringUTFChars(env, com1x_, com1x);
    (*env)->ReleaseStringUTFChars(env, com1y_, com1y);
    (*env)->ReleaseStringUTFChars(env, N1_, N1);
    (*env)->ReleaseStringUTFChars(env, sid_, sid);
    (*env)->ReleaseStringUTFChars(env, alpha_, alpha);
    (*env)->ReleaseStringUTFChars(env, beta_, beta);
    (*env)->ReleaseStringUTFChars(env, zeta_, zeta);

    result = (*env)->NewObjectArray(env, 8, jclass1, (*env)->NewStringUTF(env, ""));
    epoint_get(w1, x, y);
    cotstr(x, tempChars);
    (*env)->SetObjectArrayElement(env, result, 0, (*env)->NewStringUTF(env, tempChars));
    cotstr(y, tempChars);
    (*env)->SetObjectArrayElement(env, result, 1, (*env)->NewStringUTF(env, tempChars));

    epoint_get(com, x, y);
    cotstr(x, tempChars);
    (*env)->SetObjectArrayElement(env, result, 2, (*env)->NewStringUTF(env, tempChars));
    cotstr(y, tempChars);
    (*env)->SetObjectArrayElement(env, result, 3, (*env)->NewStringUTF(env, tempChars));

    cotstr(N2, tempChars);
    (*env)->SetObjectArrayElement(env, result, 4, (*env)->NewStringUTF(env, tempChars));
    (*env)->SetObjectArrayElement(env, result, 5, (*env)->NewStringUTF(env, message));
    (*env)->SetObjectArrayElement(env, result, 6, (*env)->NewStringUTF(env, hexdigest));

    (*env)->SetObjectArrayElement(env, result, 7, (*env)->NewStringUTF(env, key));

    mirkill(x);
    mirkill(y);
    mirkill(d);
    mirkill(k1);
    mirkill(N2);
    mirkill(sum);
    mirkill(big1);

    return result;
}


JNIEXPORT jint JNICALL
Java_com_sunshuzhou_experiment_1miracl_Verify_verifyInClient(JNIEnv *env, jclass type, jstring key_,
                                                             jstring m1_, jstring t1_) {
    const char *key = (*env)->GetStringUTFChars(env, key_, 0);
    const char *m1 = (*env)->GetStringUTFChars(env, m1_, 0);
    const char *t1 = (*env)->GetStringUTFChars(env, t1_, 0);
    unsigned char digest[20], hexdigest[40];
    int i;
    jint result = 1;

    hmac_sha1(key, strlen(key), m1, strlen(m1), digest, 20);
    i = 0;
    for (i = 0; i < 20; ++i) {
        sprintf(&hexdigest[i * 2], "%02x", digest[i]);
    }


    for (i = 0; i < 40; ++i) {
        if (hexdigest[i] != t1[i]) {
            result = 0;
            break;
        }
    }

    (*env)->ReleaseStringUTFChars(env, key_, key);
    (*env)->ReleaseStringUTFChars(env, m1_, m1);
    (*env)->ReleaseStringUTFChars(env, t1_, t1);
    return result;
}