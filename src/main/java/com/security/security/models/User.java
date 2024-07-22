package com.security.security.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Builder
@Table (name = "users")
// userDetails is an interface provided by spring security which provides authentication and authorization mechanisms
public class User implements UserDetails {

    @Id
    private UUID id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;



    @PrePersist
    public void generateId(){
        if(this.id == null){
            this.id = UUID.randomUUID();
        }
    }

    // Returns the authorities granted to the user.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    // Indicates whether the user's account is expired. Returning true means the account is valid
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // Indicates whether the user is locked or unlocked. Returning true means the account is not locked
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // Indicates whether the user's credentials (password) are expired. Returning true means the credentials are valid.
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // Indicates whether the user is enabled or disabled. Returning true means the user is enabled.

    @Override
    public boolean isEnabled() {
        return true;
    }
}

// Implementing UserDetails allows your User class to seamlessly integrate with Spring Security, making it easier to handle authentication and authorization. It leverages Spring Security's built-in mechanisms, reducing the amount of custom code you need to write and maintain.
