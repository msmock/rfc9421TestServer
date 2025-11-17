package org.fnm.rfc9421TestServer;

public class ParseMetadataTest {

    public static void main(String[] args) {

        String signature_input =
                "sig1=(\"@method\" \"@target-uri\" \"authorization\" " +
                        "\"content-digest\");" +
                        "created=1763324281;" +
                        "keyid=\"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\";tag=\"fapi-2-request\"";

        String[] parts = signature_input.split(";");

        String timestampPart = parts[1];
        System.out.println(timestampPart);
        String timeInMillis = timestampPart.split("=")[1];
        System.out.println(timeInMillis);
    }
}
