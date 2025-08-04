package com.ag.webauthn.controller;



import com.ag.webauthn.repository.InMemoryCredentialRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/webauthn")
public class WebAuthnController {

    @GetMapping("/register")
    public String showRegistrationPage() {
        return "registration";
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    private final RelyingParty relyingParty;
    private final InMemoryCredentialRepository credentialRepository;

    private final Map<String, PublicKeyCredentialCreationOptions> registrationCache = new ConcurrentHashMap<>();
    private final Map<String, AssertionRequest> loginCache = new ConcurrentHashMap<>();

    public WebAuthnController(RelyingParty relyingParty, InMemoryCredentialRepository credentialRepository) {
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

//        UserIdentity user = existingUser.orElseGet(() -> {
//            try {
//                byte[] userIdBytes = new byte[32];
//                return UserIdentity.builder()
//                        .name(username)
//                        .displayName(username)
//                        .id(ByteArray.fromBase64Url(username.getBytes().toString()))
//                        .build();
//            } catch (Base64UrlException e) {
//                throw new RuntimeException(e);
//            }
//        });

        PublicKeyCredentialCreationOptions request = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(user)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(ResidentKeyRequirement.PREFERRED)
                                .userVerification(UserVerificationRequirement.PREFERRED)
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
    public String startLogin(@RequestBody Map<String, String> body) {
        String username = body.get("username");

        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build());

        loginCache.put(username, request);
        try {
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/login/finish")
    public String finishLogin(@RequestBody String publicKeyCredentialJson) throws IOException {


        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                PublicKeyCredential.parseAssertionResponseJson(publicKeyCredentialJson);

        String username = credentialRepository.getUsernameByCredentialId(pkc.getId());
        AssertionRequest request = loginCache.get(username);


        String credentialIdHex = pkc.getId().getHex();
        System.out.println("🔍 Login attempt with credentialId (hex): " + credentialIdHex);


        System.out.println(" - Resolved username: " + username);

// Print all known credential IDs for the user
        Set<PublicKeyCredentialDescriptor> userCredentials = credentialRepository.getCredentialIdsForUsername(username);
        System.out.println(" - Known credentials for user:");
        userCredentials.forEach(c -> System.out.println("   • " + c.getId().getHex()));


        AssertionResult result = null;
        try {
            result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());
        } catch (AssertionFailedException e) {
            throw new RuntimeException(e);
        }

        if (result.isSuccess()) {
            credentialRepository.updateSignatureCount(
                    username,
                    result.getCredentialId(),
                    result.getSignatureCount(),
                    Optional.of(result.isBackedUp())
            );


            return result.getUsername();
        }

        throw new RuntimeException("Authentication failed");
    }
}
