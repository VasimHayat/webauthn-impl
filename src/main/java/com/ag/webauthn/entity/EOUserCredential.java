package com.ag.webauthn.entity;

import com.yubico.webauthn.data.ByteArray;
import jakarta.persistence.*;
        import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "eousercredential")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EOUserCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false) // Explicit FK to users table
    private EOUser user;

    @Column(nullable = false, unique = true, columnDefinition = "BYTEA")
    private byte[] credentialId;

    @Column(nullable = false, unique = true,columnDefinition = "BYTEA")
    private byte[] publicKeyCose;

    private long signatureCount;

    private Boolean isDiscoverable;
    private Boolean backupEligible;
    private Boolean backedUp;

    @Column(columnDefinition = "BYTEA")
    private byte[] attestationObject;

    @Column(columnDefinition = "BYTEA")
    private byte[] clientDataJSON;

    private Instant lastUsed;
}
