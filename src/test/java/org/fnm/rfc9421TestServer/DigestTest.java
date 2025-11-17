package org.fnm.rfc9421TestServer;

import org.apache.commons.codec.digest.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestTest {

    public static void main(String[] args) {

        String inputString = "Hello, World";
        System.out.println("input string is "+ inputString);

        String sha256hex = DigestUtils.sha256Hex(inputString);
        System.out.println("sha256 hash is "+sha256hex);

        String jsonString = "{\n" + "  \"kty\": \"EC\",\n" +
                "  \"alg\": \"ES256\",\n" +
                "  \"crv\": \"P-256\",\n" +
                "  \"x\": \"R-z3wlMAAQ73arr3JkxfP04woVLm1zHJXX2IGCm7z5c\",\n" +
                "  \"y\": \"zs5TKDbreY-5rUqx1xiMc1aKP9CWq3dL6wZJ3wVTf50\",\n" +
                "  \"d\": \"E67QqVgry3Y7vlMyuEID4CRbubQON9Bf-PLaB3lIdFs\",\n" +
                "  \"kid\": \"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\",\n" +
                "  \"use\": \"sig\"\n" +
                "}";

        System.out.println("jsonString is "+jsonString);

        sha256hex = DigestUtils.sha256Hex(jsonString);
        System.out.println("sha256 hash is "+sha256hex);

    }
}

