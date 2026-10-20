package com.phishguard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.User;

/**
 * UserDetailsService backed by our MySQL user table.
 * Passwords are stored as bcrypt hashes.
 */
@Configuration
public class UserDetailsServiceImpl {

    private final com.phishguard.repository.UserRepository userRepository;

    public UserDetailsServiceImpl(com.phishguard.repository.UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            com.phishguard.model.User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            UserBuilder builder = User.builder()
                    .username(user.getUsername())
                    .password(user.getPasswordHash())
                    .roles(user.getRole().replace("ROLE_", ""));
            return builder.build();
        };
    }
}
