package com.ag.webauthn.repository;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.*;

import com.yubico.webauthn.data.ByteArray;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Repository
public class InMemoryCredentialRepository  {

    private static class StoredCredential {
        final String username;
        final UserIdentity userIdentity;
        final ByteArray credentialId;
        final ByteArray publicKeyCose;
        long signatureCount;
        final Optional<Boolean> isDiscoverable;
        final Optional<Boolean> backupEligible;
        Optional<Boolean> backedUp;
        final ByteArray attestationObject;
        final ByteArray clientDataJSON;
        Instant lastUsed;

        StoredCredential(String username,
                         UserIdentity userIdentity,
                         ByteArray credentialId,
                         ByteArray publicKeyCose,
                         long signatureCount,
                         Optional<Boolean> isDiscoverable,
                         Optional<Boolean> backupEligible,
                         Optional<Boolean> backedUp,
                         ByteArray attestationObject,
                         ByteArray clientDataJSON) {
            this.username = username;
            this.userIdentity = userIdentity;
            this.credentialId = credentialId;
            this.publicKeyCose = publicKeyCose;
            this.signatureCount = signatureCount;
            this.isDiscoverable = isDiscoverable;
            this.backupEligible = backupEligible;
            this.backedUp = backedUp;
            this.attestationObject = attestationObject;
            this.clientDataJSON = clientDataJSON;
            this.lastUsed = Instant.now();
        }
    }

    private final Map<String, UserIdentity> users = new ConcurrentHashMap<>();
    private final Map<ByteArray, StoredCredential> credentials = new ConcurrentHashMap<>();
    private final Map<String, List<ByteArray>> credentialsByUsername = new ConcurrentHashMap<>();

    private final Map<String, UserIdentity> userIdentityByUsername = new ConcurrentHashMap<>();
    private final Map<ByteArray, String> usernameByUserHandle = new ConcurrentHashMap<>();


    public void saveUserIdentity(UserIdentity userIdentity) {
        userIdentityByUsername.put(userIdentity.getName(), userIdentity);
        usernameByUserHandle.put(userIdentity.getId(), userIdentity.getName());
    }


   // @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return credentialsByUsername.getOrDefault(username, Collections.emptyList())
                .stream()
                .map(id -> PublicKeyCredentialDescriptor.builder()
                        .id(id)
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .build())
                .collect(Collectors.toSet());
    }

   // @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.ofNullable(users.get(username)).map(UserIdentity::getId);
    }

  //  @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return users.values().stream()
                .filter(u -> u.getId().equals(userHandle))
                .map(UserIdentity::getName)
                .findFirst();
    }


   // @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        System.out.println("🔍 lookup() called:");
        System.out.println(" - credentialId: " + credentialId.getHex());
        System.out.println(" - userHandle:   " + userHandle.getHex());

        StoredCredential sc = credentials.get(credentialId);

        if (sc == null) {
            System.out.println("❌ Credential not found in credentials map.");
            return Optional.empty();
        }

        System.out.println("✅ Found credential. Comparing userHandle...");
        System.out.println(" - Stored userHandle: " + sc.userIdentity.getId().getHex());

        if (sc.userIdentity.getId().equals(userHandle)) {
            System.out.println("✅ userHandle matches. Returning credential.");
            return Optional.of(RegisteredCredential.builder()
                    .credentialId(sc.credentialId)
                    .userHandle(sc.userIdentity.getId())
                    .publicKeyCose(sc.publicKeyCose)
                    .signatureCount(sc.signatureCount)
                    .build());
        } else {
            System.out.println("❌ userHandle mismatch.");
            return Optional.empty();
        }
    }


    //@Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {

        if (!credentials.containsKey(credentialId)) {
            System.out.println("❌ Credential ID not found in map.");
        } else {
            System.out.println("✅ Credential found, returning RegisteredCredential.");
        }
        return credentials.values().stream()
                .filter(sc -> sc.credentialId.equals(credentialId))
                .map(sc -> RegisteredCredential.builder()
                        .credentialId(sc.credentialId)
                        .userHandle(sc.userIdentity.getId())
                        .publicKeyCose(sc.publicKeyCose)
                        .signatureCount(sc.signatureCount)
                        .build())
                .collect(Collectors.toSet());


    }

    // Helpers used by your controller:

    public Optional<UserIdentity> getUserIdentityByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public String getUsernameByUserHandle(ByteArray userHandle) {
        return getUsernameForUserHandle(userHandle)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user handle"));
    }

    public String getUsernameByCredentialId(ByteArray credentialId) {
        StoredCredential sc = credentials.get(credentialId);
        if (sc == null) {
            throw new IllegalArgumentException("Unknown credential ID");
        }
        return sc.username;
    }

    public void storeCredential(String username,
                                PublicKeyCredentialDescriptor keyId,
                                ByteArray publicKeyCose,
                                long signatureCount,
                                Optional<Boolean> isDiscoverable,
                                Optional<Boolean> backupEligible,
                                Optional<Boolean> backedUp,
                                ByteArray attestationObject,
                                ByteArray clientDataJSON) {

        // Reuse existing UserIdentity or create one with a consistent userHandle
        UserIdentity user = userIdentityByUsername.computeIfAbsent(username, u -> {
            ByteArray userHandle = new ByteArray(UUID.nameUUIDFromBytes(username.getBytes()).toString().getBytes());

            UserIdentity newUser = UserIdentity.builder()
                    .name(username)
                    .displayName(username)
                    .id(userHandle)
                    .build();

            usernameByUserHandle.put(userHandle, username);
            return newUser;
        });

        users.putIfAbsent(username, user); // for CredentialRepository methods

        StoredCredential sc = new StoredCredential(
                username, user,
                keyId.getId(),
                publicKeyCose,
                signatureCount,
                isDiscoverable,
                backupEligible,
                backedUp,
                attestationObject,
                clientDataJSON
        );

        credentials.put(keyId.getId(), sc);
        credentialsByUsername.computeIfAbsent(username, k -> new ArrayList<>())
                .add(keyId.getId());

        System.out.println("🗃️ Storing credential in repository:");
        System.out.println(" - username: " + username);
        System.out.println(" - credentialId (hex): " + keyId.getId().getHex());
        System.out.println(" - publicKey: " + publicKeyCose.getHex());
        System.out.println(" - userHandle (hex): " + user.getId().getHex());
        System.out.println(" - signatureCount: " + signatureCount);
    }


    public void updateSignatureCount(String username,
                                     ByteArray credentialId,
                                     long newSignatureCount,
                                     Optional<Boolean> backedUp) {
        StoredCredential sc = credentials.get(credentialId);
        if (sc != null && sc.username.equals(username)) {
            sc.signatureCount = newSignatureCount;
            sc.backedUp = backedUp;
            sc.lastUsed = Instant.now();
        }
    }
}
