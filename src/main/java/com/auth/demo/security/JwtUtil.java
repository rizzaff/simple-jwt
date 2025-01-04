package com.auth.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    private static final String SECRET_KEY = "my-secret-key";

    public String generateToken(String username, String userId, String role) {

        String requestId = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId); // Add user ID
        claims.put("role", role);    // Add user role
        claims.put("requestId", requestId); // Add request ID

        logger.info("[JwtUtil] Generating token for user: " + username + " with request ID: " + requestId);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours validity
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token, String username) {
        String extractedUsername = extractUsername(token);
        return username.equals(extractedUsername);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    // Example to extract specific claims
    public String extractClaim(String token, String claimKey) {
        Claims claims = extractAllClaims(token);
        return claims.get(claimKey, String.class);
    }
}

