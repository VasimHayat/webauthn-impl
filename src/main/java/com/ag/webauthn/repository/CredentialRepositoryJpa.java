package com.ag.webauthn.repository;


import com.ag.webauthn.entity.EOUser;
import com.ag.webauthn.entity.EOUserCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CredentialRepositoryJpa extends JpaRepository<EOUserCredential, Long> {
    Optional<EOUserCredential> findByCredentialId(byte[] credentialId);
    List<EOUserCredential> findAllByUser(EOUser user);

}
