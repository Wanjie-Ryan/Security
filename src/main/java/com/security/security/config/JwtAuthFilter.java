package com.security.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// This class is responsible for filtering HTTP requests and validating JWT tokens.
//This filter intercepts every HTTP request to ensure the request has a valid JWT token and, if valid, sets up the security context for that request.

// everytime a user sends a request from the frontend, the filter must be fired
@Component
@RequiredArgsConstructor // generates a constructor with required arguments (final fields or fields with @NonNull annotations).
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    public JwtService jwtService;
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        // this is a class that extracts the email or username that is from the token


        String authHeader = request.getHeader("Authorization");
        String jwt;
        String email;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            // call the filter chain and pass it to the next filter
            filterChain.doFilter(request,response);
            return;
        }

        // extracting the token from the authHeader
        // the index 7 is used to remove the 'Bearer ' prefix from the token
        jwt = authHeader.substring(7);
        email = jwtService.extractEmail(jwt);

        // after extracting the token from the authHeader, we need to extract the email or whatever that was passed into the token using another class method.
        // if userEmail is present and user is not authenticated, wee fetch the suer details from the DB
        // Authenticate User: If the email is present and the user is not already authenticated:
        //Load the user details from the database.
        //Validate the token.
        //Create an UsernamePasswordAuthenticationToken and set the authentication in the security context.
        if(email != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
            if(jwtService.isTokenvalid(jwt, userDetails)){
                // if username is valid create an object of UsernamePasswordAuthenticationToken, it is needed to update the securitycontext
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // updating the securitycontextholder
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }


        }

        // call the filter chain and pass it to the next filter
        filterChain.doFilter(request,response);


    }
}
