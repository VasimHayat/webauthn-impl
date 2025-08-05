package com.ag.webauthn.repository;


import com.ag.webauthn.entity.EOUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<EOUser, Long> {
    Optional<EOUser> findByUsername(String username);
    Optional<EOUser> findByUserHandle(byte[] userHandle);
}
