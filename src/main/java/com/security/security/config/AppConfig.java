package com.security.security.config;

import com.security.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AppConfig {

    // This class contains beans and configurations that are crucial for authentication, such as the UserDetailsService, AuthenticationProvider, AuthenticationManager, and PasswordEncoder.

    @Autowired
    private UserRepository userRepository;

//    This bean provides a UserDetailsService implementation which is used to load user-specific data during authentication.
//    It fetches the user from the database by email. If the user is not found, it throws a UsernameNotFoundException.



    @Bean
    public UserDetailsService userDetailsService(){
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // his bean sets up a DaoAuthenticationProvider, which is responsible for fetching user details and encoding passwords.
    //It uses the UserDetailsService and PasswordEncoder defined in this configuration
    @Bean
    public AuthenticationProvider authProvider(){

        // responsible for fetching user details and encoding passwords
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;

    }

    // This bean provides an AuthenticationManager, which is used to handle authentication requests
    @Bean
    public AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();

    }

    //This bean provides a PasswordEncoder which is used to encode passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
