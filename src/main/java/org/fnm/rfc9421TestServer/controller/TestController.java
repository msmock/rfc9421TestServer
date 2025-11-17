package org.fnm.rfc9421TestServer.controller;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/hello")
    public String sayHello() {
        return "You called the GET endpoint.";
    }

    @PostMapping("/verify")
    public String createData(@RequestHeader Map<String, String> headers, @RequestBody String content) {

        headers.forEach((key, value) -> {
            String headerAsString = String.format("%s = %s", key, value);
            System.out.println(headerAsString);
        });

        String contentDigest = headers.get("content-digest");
        String signatureInput = headers.get("signature-input");
        String signature = headers.get("signature");

        System.out.println("Received data: " + content);
        return content;
    }
}