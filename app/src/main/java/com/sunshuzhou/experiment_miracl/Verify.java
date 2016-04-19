package com.sunshuzhou.experiment_miracl;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class Verify {


    public static BigInteger fromPassword(String password) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            result = result.shiftLeft(8);
            result = result.add(BigInteger.valueOf((int) c & 0xFF));
        }
        return result;
    }

    public static Map<String, String> compute(JSONObject response, BigInteger sum) throws JSONException {
        String ux = response.get("ux").toString();
        String uy = response.get("uy").toString();
        String u1x = response.get("u1x").toString();
        String u1y = response.get("u1y").toString();
        String wx = response.get("wx").toString();
        String wy = response.get("wy").toString();
        String com1x = response.get("com1x").toString();
        String com1y = response.get("com1y").toString();
        String N1 = response.get("N1").toString();
        String sid = response.get("sid").toString();
        String alpha = response.get("alpha").toString();
        String beta = response.get("beta").toString();
        String gama = response.get("gama").toString();

        String[] strings = computeForServer(ux, uy, u1x, u1y, wx, wy, com1x, com1y, N1, sid, alpha, beta, gama);

        Map<String, String> map = new HashMap<>();
        map.put("w1x", strings[0]);
        map.put("w1y", strings[1]);
        map.put("comx", strings[2]);
        map.put("comy", strings[3]);
        map.put("N2", strings[4]);
        map.put("message0", strings[5]);
        map.put("tag0", strings[6]);
        map.put("key", strings[7]);
        map.put("sid", sid);
        return map;
    }

    public static boolean verify(String key, String m1, String t1) {
        SHA1Digest digest = new SHA1Digest();
        HMac hmac = new HMac(digest);
        CipherParameters params = new KeyParameter(key.getBytes());
        hmac.init(params);
        byte bytes[] = m1.getBytes();
        hmac.update(bytes, 0, bytes.length);
        byte output[] = new byte[20];
        hmac.doFinal(output, 0);
        Formatter formatter = new Formatter();
        for (byte b:output) {
            formatter.format("%02x", b);
        }
        String tag = formatter.toString();
        return tag.equals(t1);
//        return verifyInClient(key, m1, t1) == 1;
    }


    public static native String[] computeForServer(String ux, String uy, String u1x, String u1y, String wx, String wy, String com1x, String com1y, String N1, String sid, String alpha, String beta, String zeta);

    public static native int verifyInClient(String key, String m1, String t1);




}
