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

        // get the timestamp
        String signatureMetadata = headers.get("signature-input");
        String[] metadataParts = signatureMetadata.split(";");

        // String requestTimestampAsString = metadataParts[1].split("=")[1];
        // Instant requestTimestamp = Instant.ofEpochSecond(Long.parseLong(requestTimestampAsString));

        // Create a verifier.
        JWK publicJWK = JWK.parse(SIGNING_KEY).toPublicJWK();

        FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
                .setAuthorization(headers.get("authorization"))
                .setTargetUri(URI.create("http://localhost:8080/api/verify"))
                .setContentDigest(headers.get("content-digest"))
                .setMethod("POST")
                .setVerificationKey(publicJWK);

        // Verify the signature.
        List<ComponentIdentifier> componentIdentifiers = Arrays.asList(
                new ComponentIdentifier("authorization"),
                new ComponentIdentifier("@target-uri"),
                new ComponentIdentifier("content-digest"),
                new ComponentIdentifier("@method")
        );

        SignatureMetadataParameters parameters = new SignatureMetadataParameters().setTag("fapi-2-request").setCreated(Instant.now());
        SignatureMetadata metadata = new SignatureMetadata(componentIdentifiers, parameters);

        // parse the signature
        String signatureAsString = headers.get("signature").trim();
        System.out.println("signatureAsString: " + signatureAsString);

        String[] signatureParts = signatureAsString.split(":");
        byte[] parsedSignature = Base64.getDecoder().decode(signatureParts[1]); // failed

        System.out.println("part 1 is " + signatureParts[1]);
        VerificationInfo verificationInfo = verifier.verify(parsedSignature, metadata);

        System.out.println("Verification result : " + verificationInfo.isVerified());
        System.out.println("Reason: " + verificationInfo.getReason());

        return content;
    }
}