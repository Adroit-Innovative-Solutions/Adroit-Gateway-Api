package io.datquad.ApiGateway.service;

import io.datquad.ApiGateway.exceptions.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private final Key key;
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    public JwtService(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Validate the token by checking signature and expiration only
    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new InvalidTokenException("Token is missing or empty.");
        }

        try {
            Claims claims = getClaims(token);

            // Validate expiration
            if (claims.getExpiration().before(new Date())) {
                throw new InvalidTokenException("Token has expired.");
            }

            return true;
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            throw new InvalidTokenException("Invalid or malformed token.");
        }
    }

    // Extract the username (email) from the token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // Parse and extract claims
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
