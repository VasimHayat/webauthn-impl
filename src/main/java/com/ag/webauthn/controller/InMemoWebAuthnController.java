package com.ag.webauthn.controller;



import com.ag.webauthn.repository.InMemoryCredentialRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/v1/webauthn")
public class InMemoWebAuthnController {


    private final RelyingParty relyingParty;
    private final InMemoryCredentialRepository credentialRepository;

    private final Map<String, PublicKeyCredentialCreationOptions> registrationCache = new ConcurrentHashMap<>();
    private final Map<String, AssertionRequest> loginCache = new ConcurrentHashMap<>();

    public InMemoWebAuthnController(RelyingParty relyingParty, InMemoryCredentialRepository credentialRepository) {
        this.relyingParty = relyingParty;
        this.credentialRepository = credentialRepository;
    }

    @PostMapping("/register/start")
    public String startRegistration(@RequestBody Map<String, String> body) throws IOException {
        String username = body.get("username");

        Optional<UserIdentity> existingUser = credentialRepository.getUserIdentityByUsername(username);

        UserIdentity user = existingUser.orElseGet(() -> {
            byte[] userIdBytes = new byte[32];
            new SecureRandom().nextBytes(userIdBytes);
            UserIdentity newUser = UserIdentity.builder()
                    .name(username)
                    .displayName(username)
                    .id(new ByteArray(userIdBytes))
                    .build();
            credentialRepository.saveUserIdentity(newUser);
            return newUser;
        });



        PublicKeyCredentialCreationOptions request = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(user)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(ResidentKeyRequirement.PREFERRED)
                                .userVerification(UserVerificationRequirement.PREFERRED)
                                .authenticatorAttachment(AuthenticatorAttachment.PLATFORM) // Optional: enforce platform auth
                                .build())
                        .build()
        );

        registrationCache.put(username, request);
        return request.toCredentialsCreateJson();
    }

    @PostMapping("/register/finish")
    public String finishRegistration(@RequestBody Map<String, String> body) throws IOException, RegistrationFailedException {
        String username = body.get("username");
        String publicKeyCredentialJson = body.get("credential");

        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialJson);

        PublicKeyCredentialCreationOptions request = registrationCache.get(username);

        RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                .request(request)
                .response(pkc)
                .build());

        credentialRepository.storeCredential(
                username,
                result.getKeyId(),
                result.getPublicKeyCose(),
                result.getSignatureCount(),
                result.isDiscoverable(), // already returns Optional<Boolean>
                Optional.of(result.isBackupEligible()), // wrap boolean
                Optional.of(result.isBackedUp()),       // wrap boolean
                pkc.getResponse().getAttestationObject(),
                pkc.getResponse().getClientDataJSON()
        );

        return "Registration successful";
    }


    @PostMapping("/login/start")
    public Map<String, Object> startLogin(@RequestBody Map<String, String> body) {
        Optional<String> maybeUsername = Optional.ofNullable(body.get("username"))
                .filter(s -> !s.isEmpty());

        StartAssertionOptions.StartAssertionOptionsBuilder optionsBuilder = StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.PREFERRED);

        maybeUsername.ifPresent(optionsBuilder::username);

        AssertionRequest request = relyingParty.startAssertion(optionsBuilder.build());

        // Use username as cache key if provided; otherwise generate a temporary ID
        String cacheKey = maybeUsername.orElse(UUID.randomUUID().toString());
        loginCache.put(cacheKey, request);

        System.out.println("cacheKey "+cacheKey);

        Map<String, Object> response = new HashMap<>();
        response.put("requestId", cacheKey); // Return the login cache key


        try {
            response.put("reqData", new ObjectMapper().readValue(request.toCredentialsGetJson(), Map.class));
           // response.put("request", request.toCredentialsGetJson());
            return response;
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to convert AssertionRequest to JSON", e);
        }
    }

    @PostMapping("/login/finish")
    public String finishLogin(@RequestBody Map<String, Object> body) throws IOException {
        // Extract requestId (used as the cache key for AssertionRequest)
        String requestId = (String) body.get("requestId");
        if (requestId == null || !loginCache.containsKey(requestId)) {
            throw new IllegalArgumentException("Invalid or missing requestId");
        }

        // Extract credential object sent from client
        Map<String, Object> credentialMap = (Map<String, Object>) body.get("credential");

        // Convert credential JSON to PublicKeyCredential object
        ObjectMapper mapper = new ObjectMapper();
        String credentialJson = mapper.writeValueAsString(credentialMap);

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                PublicKeyCredential.parseAssertionResponseJson(credentialJson);

        // Retrieve the original AssertionRequest from cache
        AssertionRequest request = loginCache.get(requestId);

        // Get the username associated with the credentialId
        String username = credentialRepository.getUsernameByCredentialId(pkc.getId());

        System.out.println("🔍 Login attempt with credentialId (hex): " + pkc.getId().getHex());
        System.out.println(" - Resolved username: " + username);

        Set<PublicKeyCredentialDescriptor> knownCredentials = credentialRepository.getCredentialIdsForUsername(username);
        System.out.println(" - Known credentials for user:");
        knownCredentials.forEach(c -> System.out.println("   • " + c.getId().getHex()));

        // Perform assertion verification
        AssertionResult result;
        try {
            result = relyingParty.finishAssertion(
                    FinishAssertionOptions.builder()
                            .request(request)
                            .response(pkc)
                            .build()
            );
        } catch (AssertionFailedException e) {
            e.printStackTrace();
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }

        // Success: update counter and return username
        if (result.isSuccess()) {
            credentialRepository.updateSignatureCount(
                    username,
                    result.getCredentialId(),
                    result.getSignatureCount(),
                    Optional.of(result.isBackedUp())
            );

            // Optionally: clean up cache
            loginCache.remove(requestId);

            return "Login successful as " + result.getUsername();
        }

        throw new RuntimeException("Authentication failed");
    }

}
