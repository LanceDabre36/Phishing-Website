package com.phishguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * PhishGuard - Phishing Website Detection System
 *
 * Entry point for the Spring Boot application. The trained Weka model is loaded
 * lazily by the PredictionService at startup (see ml package).
 */
@SpringBootApplication
public class PhishGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishGuardApplication.class, args);
    }
}
