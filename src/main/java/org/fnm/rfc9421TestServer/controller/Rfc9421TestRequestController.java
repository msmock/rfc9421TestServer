package org.fnm.rfc9421TestServer.controller;

import com.authlete.hms.*;
import com.authlete.hms.fapi.FapiResourceRequestVerifier;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

@RestController
@RequestMapping("/api")
public class Rfc9421TestRequestController {

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
                SignatureEntry.scan(signatureField, signatureInputField, null);

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
        // Typically there is only one signature, but there may be more
        for (SignatureEntry sigEntry : sigEntries.values()) {
            VerificationInfo verificationInfo = verifier.verify(sigEntry);
            System.out.println("Verification result : " + verificationInfo.isVerified());
            System.out.println("Reason: " + verificationInfo.getReason());
        }

        // TODO response only, if all are verified

        // build the response
        String token = "Error while creating the token";
        try {

            Algorithm algorithm = Algorithm.HMAC512("your-secret-key");

            Map<String, String> extensions = new HashMap<>();
            extensions.put("ihe_iua", "{\"subject_name\":\"<NAME>\",\"home_community_id\":\"urn:oid:1.2.3.4\"}");
            extensions.put("ch_epr", "{\"user_id\":\"2000000090092\",\"user_id_qualifier\":\"urn:gs1:gln\"}");

            token = JWT.create()
                    .withIssuer("RFC9421TestServer")
                    .withSubject("UserId-bfe8a208-b9d0-4012-b2f5-168b949fc3cb")
                    .withAudience("http://pixmResourceServerURL.ch")
                    .withIssuedAt(Instant.now())
                    .withNotBefore(Instant.now())
                    .withExpiresAt(Instant.now().plusSeconds(300))
                    .withJWTId(UUID.randomUUID().toString())
                    .withClaim("userId", "123456")
                    .withClaim("scope", "user%2F*.*+openid+fhirUser+purpose_of_use%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.5%7CAUTO+subject_role%3Durn%3Aoid%3A2.16.756.5.30.1.127.3.10.6%7CTC")
                    .withClaim("extensions", extensions)
                    .sign(algorithm);

            System.out.println("Generated Token: " + token);

        } catch (JWTCreationException exception) {
            System.err.println("Error creating JWT: " + exception.getMessage());
        }

        return token;
    }
}