package com.adena.userservicemicroservice.service;


import com.adena.userservicemicroservice.models.Users;
import com.adena.userservicemicroservice.models.Role;
import com.adena.userservicemicroservice.respository.UserRepository;
import com.adena.userservicemicroservice.securityconfig.models.Authorization;
import com.adena.userservicemicroservice.securityconfig.repository.AuthorizationRepository;
import com.nimbusds.jose.JOSEException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class JwtTokenProvider {

    @Value("${app.jwtExpirationMs}")
    private long jwtExpirationMs;

    @Autowired
    @Qualifier("jwkSource")
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthorizationRepository authorizationRepository;

    public String generateToken(String username) throws JOSEException {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        Optional<Users> userOptional = userRepository.findByEmail(username);
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        Users user = userOptional.get();
        List<String> roles = user.getRoles().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toList());

        String jti = UUID.randomUUID().toString();

        // Get the RSA key from the JWKSource
        RSAKey rsaKey = getRSAKey();
        RSAPrivateKey privateKey = rsaKey.toRSAPrivateKey();

        String accessToken = Jwts.builder()
                .setSubject(username)
                .setAudience("edukan")
                .setNotBefore(now)
                .claim("scope", List.of("ADMIN"))
                .setIssuer("http://localhost:8088") // Use a dynamic issuer value
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .claim("roles", roles)
                .claim("userId", user.getId())
                .claim("jti", jti)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();

        // Save authorization data to repository
        Authorization authorization = new Authorization();
        authorization.setId(jti);
        authorization.setRegisteredClientId("client-id"); // Set appropriate client ID
        authorization.setPrincipalName(username);
        authorization.setAuthorizationGrantType("grant"); // Set appropriate grant type
        authorization.setAuthorizedScopes("read,write"); // Set appropriate scopes
        authorization.setAttributes("attributes"); // Set appropriate attributes
        authorization.setState("state"); // Set appropriate state

        authorization.setAccessTokenValue(accessToken);
        authorization.setAccessTokenIssuedAt(Instant.ofEpochMilli(now.getTime()));
        authorization.setAccessTokenExpiresAt(Instant.ofEpochMilli(expiryDate.getTime()));
        authorization.setAccessTokenMetadata("metadata"); // Set appropriate metadata
        authorization.setAccessTokenType("Bearer");
        authorization.setAccessTokenScopes(String.join(",", roles));

        Authorization response = authorizationRepository.save(authorization);

        return accessToken;
    }

//    private RSAKey getRSAKey() {
//        try {
//            // Create a JWKSelector to select RSA keys
//            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
//                    .keyType(KeyType.RSA) // Specify that we want RSA keys
//                    .build());
//
//            // Retrieve the JWK set from the JWKSource
//            JWKSet jwkSet = (JWKSet) jwkSource.get(selector,new SecurityContext() {
//                // Implement SecurityContext if necessary; otherwise, use a default implementation
//            });
//
//            // Apply the selector to the JWK set
//            List<JWK> selectedKeys = selector.select(jwkSet);
//
//            return (RSAKey) selectedKeys.stream()
//                    .filter(key -> key instanceof RSAKey)
//                    .findFirst()
//                    .orElseThrow(() -> new RuntimeException("No RSA key found"));
//        } catch (Exception e) {
//            throw new RuntimeException("Failed to retrieve RSA key from JWKSource", e);
//        }
//    }
//private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);
//
//    private RSAKey getRSAKey() {
//        try {
//            // Create a JWKSelector to select RSA keys
//            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
//                    .keyType(KeyType.RSA) // Specify that we want RSA keys
//                    .build());
//            System.out.println(jwkSource);
//
//            // Retrieve the JWK set from the JWKSource
//            JWKSet jwkSet = (JWKSet) jwkSource.get(selector,new SecurityContext() {
//                // Implement SecurityContext if necessary; otherwise, use a default implementation
//            });
//
//            if (jwkSet == null) {
//                throw new RuntimeException("JWKSet is null. No keys could be retrieved.");
//            }
//
//            // Apply the selector to the JWK set
//            List<JWK> selectedKeys = selector.select(jwkSet);
//
//            if (selectedKeys.isEmpty()) {
//                throw new RuntimeException("No RSA keys found in the JWKSet.");
//            }
//
//            return (RSAKey) selectedKeys.stream()
//                    .filter(key -> key instanceof RSAKey)
//                    .findFirst()
//                    .orElseThrow(() -> new RuntimeException("No RSA key found"));
//
//        } catch (Exception e) {
//            LOGGER.error("Failed to retrieve RSA key from JWKSource", e);
//            throw new RuntimeException("Failed to retrieve RSA key from JWKSource", e);
//        }
//    }


    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);

    //private final JWKSource<SecurityContext> jwkSource;

    public JwtTokenProvider(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    private RSAKey getRSAKey() {
        try {
            // Create a JWKSelector to select RSA keys
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
                    .keyType(KeyType.RSA) // Specify that we want RSA keys
                    .build());

            // Retrieve the JWK set from the JWKSource
            List<JWK> jwkList = jwkSource.get(selector, null);

            if (jwkList == null || jwkList.isEmpty()) {
                throw new RuntimeException("No RSA keys found in the JWKSource.");
            }

            return (RSAKey) jwkList.stream()
                    .filter(key -> key instanceof RSAKey)
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("No RSA key found"));

        } catch (Exception e) {
            LOGGER.error("Failed to retrieve RSA key from JWKSource", e);
            throw new RuntimeException("Failed to retrieve RSA key from JWKSource", e);
        }
    }

    public Claims getClaimsFromToken(String token) throws JOSEException {
        RSAKey rsaKey = getRSAKey();
        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
        return Jwts.parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsernameFromToken(String token) throws JOSEException {
        return getClaimsFromToken(token).getSubject();
    }

    public List<String> getRolesFromToken(String token) throws JOSEException {
        return getClaimsFromToken(token).get("roles", List.class);
    }
}
