## Project Summary

Artemis Financial is a financial planning firm with a public web interface. The company asked me to modernize a small Spring Boot service so it protects client data in transit and verifies files or other data during transfers. I focused on practical upgrades: I moved secrets and certificate paths out of code, enforced HTTPS/TLS, replaced a plain checksum with `HMAC-SHA-256` so integrity checks are keyed and tamper-resistant, and set modest limits on input size to reduce abuse. These changes matter because secure code protects customers, lowers business risk, and supports compliance — especially important for a finance client.

I followed the Vulnerability Assessment Process flow: identify, assess, mitigate, verify. To add layers of defense I used HTTPS for transport, `HMAC-SHA-256` for authenticated hashing, input validation, and externalized secrets. I verified function by running the app locally and checking the `/hash` endpoint over HTTPS (e.g., https://localhost:8443/hash), and I checked for new risks by scanning dependencies. Tools and habits I will reuse include Java Keytool, Spring Boot SSL config, Java’s crypto APIs, OWASP Dependency-Check, environment variables for secrets, and the Maven Wrapper. For a portfolio, I can show the HMAC controller, the TLS setup, and a short write-up that ties the changes back to the assessment flow.


### HashController (HMAC-SHA-256)

```java
package com.snhu.sslserver;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HashController implements InitializingBean {

    // Required: set via application.properties → hash.hmacSecret=${HASH_SECRET}
    @Value("${hash.hmacSecret}")
    private String hmacSecret;

    // Fail fast at startup if secret is missing
    @Override
    public void afterPropertiesSet() {
        if (hmacSecret == null || hmacSecret.trim().isEmpty()) {
            throw new IllegalStateException("HMAC secret not set. Configure hash.hmacSecret / HASH_SECRET.");
        }
    }

    @GetMapping(value = "/hash", produces = "application/json")
    public Map<String, String> hash(
            @RequestParam(value = "data", required = false) String data,
            @RequestParam(value = "name", required = false) String name
    ) throws Exception {

        // Input limits to prevent abuse
        if (data != null && data.length() > 4096) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "data too long (max 4096 chars)");
        }
        if (name != null && name.length() > 256) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name too long (max 256 chars)");
        }

        String who = (name == null || name.trim().isEmpty()) ? "Matt Kostandin" : name.trim();
        String base = (data == null || data.trim().isEmpty()) ? "Hello World Checksum!" : data.trim();

        String unique = base + " | " + who + " | " + LocalDateTime.now();
        String checksum = hmacSha256Hex(unique, hmacSecret);

        Map<String, String> out = new LinkedHashMap<>();
        out.put("algorithm", "HMAC-SHA-256");
        out.put("data", unique);
        out.put("checksum", checksum);
        return out;
    }

    private static String hmacSha256Hex(String msg, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] tag = mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(tag.length * 2);
        for (byte b : tag) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
```
