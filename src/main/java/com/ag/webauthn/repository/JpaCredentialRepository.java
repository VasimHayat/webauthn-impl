package com.ag.webauthn.repository;

import com.ag.webauthn.entity.EOUser;
import com.ag.webauthn.entity.EOUserCredential;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class JpaCredentialRepository implements CredentialRepository {

    private final UserRepository userRepository;
    private final CredentialRepositoryJpa credentialRepositoryJpa;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        Optional<EOUser> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) return Collections.emptySet();

        return credentialRepositoryJpa.findAllByUser(userOpt.get()).stream()
                .map(cred -> PublicKeyCredentialDescriptor.builder()
                        .id(new ByteArray(cred.getCredentialId()))
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new ByteArray(user.getUserHandle()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return userRepository.findByUserHandle(userHandle.getBytes())
                .map(EOUser::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return credentialRepositoryJpa.findByCredentialId(credentialId.getBytes())
                .filter(cred -> Arrays.equals(cred.getUser().getUserHandle(), userHandle.getBytes()))
                .map(cred -> RegisteredCredential.builder()
                        .credentialId(new ByteArray(cred.getCredentialId()))
                        .userHandle(new ByteArray(cred.getUser().getUserHandle()))
                        .publicKeyCose(new ByteArray(cred.getPublicKeyCose()))
                        .signatureCount(cred.getSignatureCount())
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return credentialRepositoryJpa.findByCredentialId(credentialId.getBytes())
                .map(cred -> Set.of(RegisteredCredential.builder()
                        .credentialId(new ByteArray(cred.getCredentialId()))
                        .userHandle(new ByteArray(cred.getUser().getUserHandle()))
                        .publicKeyCose(new ByteArray(cred.getPublicKeyCose()))
                        .signatureCount(cred.getSignatureCount())
                        .build()))
                .orElse(Collections.emptySet());
    }

    // Custom helper methods to persist data

    public void storeCredential(UserIdentity userIdentity,
                                PublicKeyCredentialDescriptor keyId,
                                ByteArray publicKeyCose,
                                long signatureCount,
                                Optional<Boolean> isDiscoverable,
                                Optional<Boolean> backupEligible,
                                Optional<Boolean> backedUp,
                                ByteArray attestationObject,
                                ByteArray clientDataJSON) {

        EOUser user = userRepository.findByUsername(userIdentity.getName())
                .orElseGet(() -> userRepository.save(EOUser.builder()
                        .username(userIdentity.getName())
                        .displayName(userIdentity.getDisplayName())
                        .userHandle(userIdentity.getId().getBytes())
                        .build()));

        EOUserCredential credential = EOUserCredential.builder()
                .user(user)
                .credentialId(keyId.getId().getBytes())
                .publicKeyCose(publicKeyCose.getBytes())
                .signatureCount(signatureCount)
                .isDiscoverable(isDiscoverable.orElse(null))
                .backupEligible(backupEligible.orElse(null))
                .backedUp(backedUp.orElse(null))
                .attestationObject(attestationObject.getBytes())
                .clientDataJSON(clientDataJSON.getBytes())
                .lastUsed(Instant.now())
                .build();

        credentialRepositoryJpa.save(credential);
    }

    public void updateSignatureCount(String username, ByteArray credentialId, long newSignatureCount, Optional<Boolean> backedUp) {
        credentialRepositoryJpa.findByCredentialId(credentialId.getBytes()).ifPresent(cred -> {
            cred.setSignatureCount(newSignatureCount);
            cred.setBackedUp(backedUp.orElse(null));
            cred.setLastUsed(Instant.now());
            credentialRepositoryJpa.save(cred);
        });
    }

    public String getUsernameByCredentialId(ByteArray credentialId) {
        return credentialRepositoryJpa.findByCredentialId(credentialId.getBytes())
                .map(cred -> cred.getUser().getUsername())
                .orElseThrow(() -> new NoSuchElementException("No user found for credentialId"));
    }
}
