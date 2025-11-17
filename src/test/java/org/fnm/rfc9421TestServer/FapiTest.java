package org.fnm.rfc9421TestServer;

import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

import com.authlete.hms.fapi.FapiResourceRequestSigner;
import com.authlete.hms.fapi.FapiResourceRequestVerifier;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.SigningInfo;
import com.authlete.hms.VerificationInfo;
import com.nimbusds.jose.jwk.JWK;
import org.junit.Test;

import static org.junit.Assert.*;

public class FapiTest {

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

    // The content-digest aka payload-digest value for testing; sha-256 of "{}".
    // This is the digest of a hypothetical payload. This test does not cover the creation of the digest from
    // the actual payload.
    private static final String CONTENT_DIGEST = "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:";

    private static void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException cause) {
            cause.printStackTrace();
        }
    }

    /**
     *
     */
    @Test
    public void test_default_metadata() throws ParseException, IllegalStateException, SignatureException {

        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();

        // the timestamp
        Instant requestTimestamp = Instant.now();

        // Create a signer and sign.
        FapiResourceRequestSigner signer = new FapiResourceRequestSigner()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setCreated(requestTimestamp)
                .setSigningKey(signingKey);

        // Sign
        SigningInfo signingInfo = signer.sign();

        // Check the actual signature metadata against the expected metadata
        String expectedMetadata = String.format(
                "(\"@method\" \"@target-uri\" \"authorization\" \"content-digest\")" +
                        ";created=%d;keyid=\"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\"" +
                        ";tag=\"fapi-2-request\"", requestTimestamp.getEpochSecond());

        String actualMetadata = signingInfo.getSerializedSignatureMetadata();
        assertEquals(expectedMetadata, actualMetadata);

        // Check the actual signature serialization against the expected.
        String expectedSerializedSignature = String.format(":%s:", Base64.getEncoder().encodeToString(signingInfo.getSignature()));
        String actualSerializedSignature = signingInfo.getSerializedSignature();
        assertEquals(expectedSerializedSignature, actualSerializedSignature);

        // Sleep 1 second to make Instant.now() generate a different value than 'created'.
        sleep();

        // Create a verifier.
        FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setVerificationKey(verificationKey);

        // Verify with the default signature metadata. This verification should fail.
        VerificationInfo vinfo = verifier.verify(signingInfo.getSignature(), null);
        assertFalse("Signature verification unexpectedly passed.", vinfo.isVerified());

        // Let the verifier use the 'created' value when it builds the default signature metadata.
        verifier.setCreated(requestTimestamp);

        // Verify with the default signature metadata. This verification should pass.
        vinfo = verifier.verify(signingInfo.getSignature(), null);
        assertTrue("Signature verification unexpectedly failed.", vinfo.isVerified());

        // Verify with the same signature metadata as used for signing. This verification should pass.
        vinfo = verifier.verify(signingInfo.getSignature(), signingInfo.getMetadata());
        assertTrue("Signature verification unexpectedly failed.", vinfo.isVerified());
    }


    private static FapiResourceRequestSigner createSigner(Instant created, JWK signingKey) {
        return new FapiResourceRequestSigner()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setCreated(created)
                .setSigningKey(signingKey);
    }


    private static FapiResourceRequestVerifier createVerifier(JWK verificationKey) {
        return new FapiResourceRequestVerifier()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setVerificationKey(verificationKey);
    }


    @Test
    public void test_custom_metadata() throws ParseException, IllegalStateException, SignatureException {

        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Custom metadata with a different order of component identifiers and a different order of parameters.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("content-digest"),
                        new ComponentIdentifier("@method")
                ),
                new SignatureMetadataParameters().setTag("fapi-2-request").setCreated(created)
        );

        // Sign
        SigningInfo sinfo = signer.sign(metadata);

        // Check the signature metadata.
        checkCustomMetadata(created, sinfo);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // Verify with the custom metadata. This verification should pass.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), metadata);
        assertTrue("Signature verification unexpectedly failed.", vinfo.isVerified());

        // Verify with the default metadata. This verification should fail.
        verifier.setCreated(created);
        vinfo = verifier.verify(sinfo.getSignature(), null);
        assertFalse("Signature verification unexpectedly passed.", vinfo.isVerified());
    }


    private static void checkCustomMetadata(Instant created, SigningInfo info) {
        // Expected signature metadata
        String expectedMetadata = String.format(
                "(\"authorization\" \"@target-uri\" \"content-digest\" \"@method\")" +
                        ";tag=\"fapi-2-request\";created=%d", created.getEpochSecond());

        // Actual signature metadata
        String actualMetadata = info.getSerializedSignatureMetadata();
        assertEquals(expectedMetadata, actualMetadata);
    }


    @Test
    public void test_missing_component() throws ParseException, IllegalStateException, SignatureException {
        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Signature metadata that is missing mandatory components.
        SignatureMetadata metadata = new SignatureMetadata(
                // "@target-uri" is missing.
                Arrays.asList(
                        new ComponentIdentifier("@method"),
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                        .setCreated(created)
                        .setTag("fapi-2-request")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // Verify with the same signature metadata as used for signing.
        //
        // This verification should fail because the required component
        // "@target-uri" is missing.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse("Signature verification unexpectedly passed.", vinfo.isVerified());
    }


    @Test
    public void test_expired() throws ParseException, IllegalStateException, SignatureException {
        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Signature metadata with a 'created' parameter set too far in the past,
        // causing the verifier to consider the HTTP message signature expired.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("@method"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                        .setCreated(created.minus(Duration.ofHours(1)))
                        .setTag("fapi-2-request")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // This verification should fail because the 'created' parameter
        // indicates that the HTTP message signature has expired.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse("Signature verification unexpectedly passed.", vinfo.isVerified());
    }


    @Test
    public void test_bad_tag() throws ParseException, IllegalStateException, SignatureException {
        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Signature metadata whose 'tag' parameter holds an unexpected value.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("@method"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                        .setCreated(created)
                        .setTag("unknown")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // Verify with the same signature metadata as used for signing.
        //
        // This verification should fail because the 'tag' parameter
        // holds an unexpected value.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse("Signature verification unexpectedly passed.", vinfo.isVerified());
    }
}
