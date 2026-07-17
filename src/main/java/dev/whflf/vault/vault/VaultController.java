package dev.whflf.vault.vault;

import dev.whflf.vault.vault.dto.VaultEntryRequest;
import dev.whflf.vault.vault.dto.VaultEntryResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/vault")
@RequiredArgsConstructor
public class VaultController {

    private final VaultService vaultService;

    @GetMapping
    public ResponseEntity<List<VaultEntryResponse>> getEntries(
            @AuthenticationPrincipal String email,
            @RequestHeader("X-Master-Password") String masterPassword) {
        return ResponseEntity.ok(vaultService.getEntries(email, masterPassword));
    }

    @PostMapping
    public ResponseEntity<VaultEntryResponse> createEntry(
            @AuthenticationPrincipal String email,
            @RequestHeader("X-Master-Password") String masterPassword,
            @Validated @RequestBody VaultEntryRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(vaultService.createEntry(email, masterPassword, request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<VaultEntryResponse> updateEntry(
            @AuthenticationPrincipal String email,
            @RequestHeader("X-Master-Password") String masterPassword,
            @PathVariable Long id,
            @Validated @RequestBody VaultEntryRequest request) {
        return ResponseEntity.ok(vaultService.updateEntry(email, masterPassword, id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteEntry(
            @AuthenticationPrincipal String email,
            @RequestHeader("X-Master-Password") String masterPassword,
            @PathVariable Long id) {
        vaultService.deleteEntry(email, masterPassword, id);
        return ResponseEntity.noContent().build();
    }
}
