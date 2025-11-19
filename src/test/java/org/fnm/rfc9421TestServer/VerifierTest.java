package org.fnm.rfc9421TestServer;

import com.authlete.hms.*;
import com.authlete.hms.fapi.FapiResourceRequestSigner;
import com.authlete.hms.fapi.FapiResourceRequestVerifier;
import com.nimbusds.jose.jwk.JWK;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.*;

public class VerifierTest {

    private static final String SIGNING_KEY =
            "{\n" +
                    "  \"kty\": \"EC\",\n" +
                    "  \"alg\": \"ES256\",\n" +
                    "  \"crv\": \"P-256\",\n" +
                    "  \"x\": \"R-z3wlMAAQ73arr3JkxfP04woVLm1zHJXX2IGCm7z5c\",\n" +
                    "  \"y\": \"zs5TKDbreY-5rUqx1xiMc1aKP9CWq3dL6wZJ3wVTf50\",\n" +
                    "  \"d\": \"E67QqVgry3Y7vlMyuEID4CRbubQON9Bf-PLaB3lIdFs\",\n" +
                    "  \"kid\": \"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\",\n" +
                    "  \"use\": \"sig\"\n" +
                    "}";

    // The HTTP method.
    private static final String HTTP_METHOD = "POST";
    private static final URI TARGET_URI = URI.create("https://example.com/path?key=value");
    private static final String AUTHORIZATION = "Bearer abc";
    private static final String CONTENT_DIGEST = "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:";

    @Test
    public void test_custom_metadata() throws ParseException, IllegalStateException, SignatureException {

        JWK signingKey = JWK.parse(SIGNING_KEY);
        Instant timestamp = Instant.now();

        // Create a signer
        FapiResourceRequestSigner signer = new FapiResourceRequestSigner()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setCreated(timestamp)
                .setSigningKey(signingKey);

        // Create custom metadata
        SignatureMetadata signatureMetadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("content-digest"),
                        new ComponentIdentifier("@method")
                ),
                new SignatureMetadataParameters().setTag("fapi-2-request").setCreated(timestamp)
        );

        // Sign
        SigningInfo signingInfo = signer.sign(signatureMetadata);
        System.out.println("signature after signing "+signingInfo.getSerializedSignature());

        // Check the signatureAsByteArray metadata.
        checkMetadata(timestamp, signingInfo);


        // ------------ Part II: Verify with the public key ----------------

        JWK publicKey = signingKey.toPublicJWK();

        SignatureBase signatureBase = signingInfo.getSignatureBase();

        // TODO parse signature base

        FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
                .setAuthorization(AUTHORIZATION)
                .setTargetUri(TARGET_URI)
                .setContentDigest(CONTENT_DIGEST)
                .setMethod(HTTP_METHOD)
                .setVerificationKey(publicKey);

        // byte handling
        String signatureAsString = Base64.getEncoder().encodeToString(signingInfo.getSignature());
        System.out.println("signatureAsString: " + signatureAsString);
        byte[] parsedSignature = Base64.getDecoder().decode(signatureAsString);

        // use the parsed signature to verify
        VerificationInfo vinfo = verifier.verify(parsedSignature, signatureMetadata);

        assertTrue("Signature verification unexpectedly failed.", vinfo.isVerified());

        // Verify with the message timestamp
        verifier.setCreated(timestamp);
        vinfo = verifier.verify(signingInfo.getSignature(), signatureMetadata);

        assertTrue("Signature verification unexpectedly failed.", vinfo.isVerified());
    }


    /**
     * Check if the metadata get from the signingInfo match the expected ones
     *
     * @param timestamp the timestamp
     * @param signingInfo the signing info object
     */
    private static void checkMetadata(Instant timestamp, SigningInfo signingInfo) {

        String expectedMetadata = String.format(
                "(\"authorization\" \"@target-uri\" \"content-digest\" \"@method\")" +
                        ";tag=\"fapi-2-request\";created=%d", timestamp.getEpochSecond());

        String actualMetadata = signingInfo.getSerializedSignatureMetadata();
        assertEquals(expectedMetadata, actualMetadata);
    }

 }


