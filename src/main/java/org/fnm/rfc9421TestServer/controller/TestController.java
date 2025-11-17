package org.fnm.rfc9421TestServer.controller;

import com.authlete.hms.*;
import com.authlete.hms.fapi.FapiResourceRequestSigner;
import com.authlete.hms.fapi.FapiResourceRequestVerifier;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/hello")
    public String sayHello() {
        return "You called the GET endpoint.";
    }

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

    /**
     * The general steps for verifying an HTTP message signature are as follows:
     * - Extract the signature and metadata from the Signature HTTP field.
     * - Reconstruct the Signature Base.
     * - verify that the signature is valid for the Signature Base.
     *
     * @param headers the request headers
     * @param content the content or payload of the request
     *
     * @return the result of the verification
     */
    @PostMapping("/verify")
    public String verifyHttpSignature(@RequestHeader Map<String, String> headers, @RequestBody String content) throws ParseException, SignatureException {

        headers.forEach((key, value) -> {
            String headerAsString = String.format("%s = %s", key, value);
            System.out.println(headerAsString);
        });

        String contentDigest = headers.get("content-digest");
        String signatureMetadata = headers.get("signature-input");
        String signature = headers.get("signature");
        String authZ = headers.get("authorization");
        URI uri = URI.create("http://localhost:8080/api/verify");
        JWK signingKey = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();

        // Create a verifier.
        FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
                .setMethod("POST")
                .setTargetUri(uri)
                .setAuthorization(authZ)
                .setContentDigest(contentDigest)
                .setVerificationKey(verificationKey);

        // Verify the signature.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("content-digest"),
                        new ComponentIdentifier("@method")
                ),
                new SignatureMetadataParameters().setTag("fapi-2-request").setCreated(Instant.now()) //TODO parse timestamp
        );

        VerificationInfo verificationInfo = verifier.verify(signature.getBytes(), metadata);

        System.out.println("Received data: " + content);
        return content;
    }
}