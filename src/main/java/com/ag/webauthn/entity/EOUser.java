package com.ag.webauthn.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "eouser")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EOUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    private String displayName;

    @Column(nullable = false, unique = true, columnDefinition = "BYTEA")
    private byte[] userHandle;
}
