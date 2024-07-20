package com.security.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // claims are transferred between 2 parties and are encoded in a token

    // write 2 methods to extract all the claims and another method to extract only one claim
    // static means that the key belong to this class and not any other instance of the class.

    private static final String Secret_Key = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTcyMDA3OTQyNiwiaWF0IjoxNzIwMDc5NDI2fQ.WQDomcG9AXavXxDJyPFD4avcI7arLaBFelSsbHf32Qk";

    public String extractEmail(String jwt) {

        return extractClaim(jwt, Claims::getSubject);
        // subject is the email of the user

    }

    // extracting a single claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generating a token using UserDetails alone

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    // method to generate the token with extraClaims and UserDetails
    // extraClaims enables us to add any other extra information that we want to store in our token
    // the userDetails is from an import package
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Validating the token
    public boolean isTokenvalid(String token, UserDetails userDetails){
        final String username = extractEmail(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        // the claims and the jwts all come from the jwt packages
        // the signingkey is the secret key that was used to sign the token
        // the getBody helps us to get all the claims from the token
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();


    }

    // this method return type is a key

    private Key getSigningKey() {

        byte[] keyBytes = Decoders.BASE64.decode(Secret_Key);
        // the hmac is nothing but an algorithm
        return Keys.hmacShaKeyFor(keyBytes);


    }
}
