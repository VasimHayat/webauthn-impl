package com.ag.webauthn.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.CredentialRepository;

import java.util.Set;

@Configuration
public class RelyingPartyConfig {

    @Bean
    public RelyingParty relyingParty(CredentialRepository credentialRepository) {
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id("localhost")  // your domain or relying party ID
                        .name("Demo App")
                        .build())
                .credentialRepository(credentialRepository)
                .origins(Set.of("http://localhost:8080")) // must match frontend origin
                .build();
    }
}
