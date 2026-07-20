package dev.whflf.vault.audit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class HibpClient {

    private static final int PREFIX_LENGTH = 5;

    private final RestClient restClient;

    public HibpClient(@Value("${app.hibp.api-url}") String apiUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(apiUrl)
                .defaultHeader("User-Agent", "password-manager-pet-project")
                .build();
    }

    public boolean isPasswordPwned(String password) {
        String sha1 = sha1Hex(password).toUpperCase();
        String prefix = sha1.substring(0, PREFIX_LENGTH);
        String suffix = sha1.substring(PREFIX_LENGTH);

        String response = restClient.get()
                .uri("/range/{prefix}", prefix)
                .retrieve()
                .body(String.class);

        if (response == null) {
            return false;
        }

        return response.lines()
                .map(line -> line.split(":")[0])
                .anyMatch(suffix::equals);
    }

    private String sha1Hex(String input) {
        try {
            java.security.MessageDigest md =
                    java.security.MessageDigest.getInstance("SHA-1");
            byte[] bytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        }
    }
}
