package com.blogplatform.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private final long expiratioMs;

    public JwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expiratioMs
    ){
        // Validation: Fail Fast, Better developer Experience
        if(secret == null || secret.length()<32){
            throw new IllegalArgumentException("JWT secret must be at least 32 Characters");
        }

        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.expiratioMs = expiratioMs;
    }

    public String generateToken(String userID, String email, String username){

        return Jwts.builder()
                .setSubject(userID)
                .addClaims(Map.of(
                        "email",email,
                        "username", username
                         ))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiratioMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUserId(String token){
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenValid(String token){
        try{
            extractAllClaims(token);
            return true;
        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }
}
