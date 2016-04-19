package com.sunshuzhou.experiment_miracl;

import java.math.BigInteger;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.field.FiniteField;
import org.spongycastle.math.field.FiniteFields;

public class Config {
    public static int ECC_K = 160;
    public static BigInteger ECC_B = new BigInteger("730750818665451459101842416358141509827966381903");
    public static BigInteger ECC_P = new BigInteger("1461501637330902918203684832716283019655932542983");
    public static BigInteger ECC_A = ECC_P.subtract(BigInteger.valueOf(3));
    public static BigInteger ECC_N = new BigInteger("1461501637330902918203683121663422642150372888183");
    public static ECCurve ECC = new ECCurve.Fp(ECC_P, ECC_A, ECC_B);
    public static FiniteField ECC_Fp = FiniteFields.getPrimeField(ECC_N);
    public static ECPoint ECC_G = ECC.createPoint(new BigInteger("1012746360306660395378213658174943965595577675415"), new BigInteger("75650897218223448951292550565147513994140144567"));
    public static ECPoint ECC_H = ECC.createPoint(new BigInteger("224936487907180308547085034490832824824803093939"), new BigInteger("543652889493671517302050399526044299167343581063"));

    public static String SERVER_ADDRESS = "http://121.42.174.42/";
}