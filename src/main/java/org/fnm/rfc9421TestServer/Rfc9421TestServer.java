package org.fnm.rfc9421TestServer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class Rfc9421TestServer {

	public static void main(String[] args) {
		SpringApplication.run(Rfc9421TestServer.class, args);
	}

}
