//package com.adena.userservicemicroservice.utils;
//
//import com.adena.edhukanuserservice.securityconfig.models.CustomUserDetails;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.security.oauth2.jwt.Jwt;
//
//public class JwtUtils {
//    public static long getUserIdFromToken() {
//
//        long userId = 0;
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        //OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
//
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
//            Jwt jwt = (Jwt) authentication.getPrincipal();
//            Object userIdClaim = jwt.getClaims().get("user_id"); // Assuming 'user_id' is the claim name
//
//            if (userIdClaim instanceof Number) {
//                userId = ((Number) userIdClaim).longValue();
//            }
//        }
//
//        Jwt jwt = (Jwt) authentication.getPrincipal();
//
//        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
//        String idToken = oidcUser.getIdToken().getTokenValue();
//
//        Object userDetails = (Jwt) authentication.getPrincipal();
//        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
//            Jwt jwt1 = (Jwt) authentication.getPrincipal();
//            userId = jwt1.getClaim("userId");
//        }
//        return userId;
//    }
//}
