package org.fnm.rfc9421TestServer.controller;

import com.authlete.hms.*;
import com.authlete.hms.fapi.FapiResourceRequestVerifier;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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
     * - Verify that the signature is valid for the Signature Base.
     *
     * @param headers the request headers
     * @param content the content or payload of the request
     * @return the result of the verification
     */
    @PostMapping("/verify")
    public String verifyHttpSignature(@RequestHeader Map<String, String> headers, @RequestBody String content) throws ParseException, SignatureException {

        headers.forEach((key, value) -> {
            String headerAsString = String.format("%s = %s", key, value);
            System.out.println(headerAsString);
        });

        // Parse the "Signature" HTTP field.
        String signatureFieldValue = headers.get("signature");
        SignatureField signatureField =
                SignatureField.parse(signatureFieldValue);

        // Parse the "Signature-Input" HTTP field.
        String signatureInputFieldValue = headers.get("signature-input");
        SignatureInputField signatureInputField =
                SignatureInputField.parse(signatureInputFieldValue);

        // The tag to scan.
        String tag = "fapi-2-request";

        // Mapping between a string label and a SignatureEntry instance.
        Map<String, SignatureEntry> sigEntries =
                SignatureEntry.scan(signatureField, signatureInputField, tag);

        // Create a verifier.
        JWK publicJWK = JWK.parse(SIGNING_KEY).toPublicJWK();

        FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
                .setMethod("POST")
                .setTargetUri(URI.create("http://localhost:8080/api/verify"))
                .setAuthorization(headers.get("authorization"))
                .setContentDigest(headers.get("content-digest"))
                .setVerificationKey(publicJWK);

        // Verify the signature.
        List<ComponentIdentifier> componentIdentifiers = Arrays.asList(
                new ComponentIdentifier("@method"),
                new ComponentIdentifier("@target-uri"),
                new ComponentIdentifier("authorization"),
                new ComponentIdentifier("content-digest")
        );

        // For each SignatureEntry that has the specified tag ("fapi-2-request" here)
        for (SignatureEntry sigEntry : sigEntries.values()) {
            VerificationInfo verificationInfo = verifier.verify(sigEntry);
            System.out.println("Verification result : " + verificationInfo.isVerified());
            System.out.println("Reason: " + verificationInfo.getReason());
        }

        return content;
    }
}