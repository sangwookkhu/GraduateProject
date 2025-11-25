package com.example.hybridauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class HybridauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(HybridauthApplication.class, args);
	}

}
