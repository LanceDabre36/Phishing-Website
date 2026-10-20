package com.phishguard.config;

import com.phishguard.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Spring Security configuration.
 * - Session-based auth (no JWT needed for a college project).
 * - Public pages: home, login, signup, static resources.
 * - Admin pages require ADMIN role.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final UserRepository userRepository;

    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * BCrypt password encoder used by both UserService and Spring Security.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/home", "/login", "/signup", "/error",
                                 "/scan", "/scan/**",
                                 "/css/**", "/js/**", "/images/**",
                                 "/error/**", "/favicon.ico", "/favicon.svg", "/sitemap.xml",
                                 "/robots.txt", "/llms.txt").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/history").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )
            .formLogin(login -> login
                .loginPage("/login")
                .successHandler(successHandler())
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/home")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            )
            .exceptionHandling(ex -> ex
                .accessDeniedPage("/error/403")
            );
        return http.build();
    }

    /**
     * After successful login, store the User entity in the HTTP session
     * so controllers can access it via session.getAttribute("user").
     * Returns the user to the page they originally requested (e.g. /scan),
     * falling back to /home.
     */
    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            String username = authentication.getName();
            userRepository.findByUsername(username).ifPresent(user ->
                request.getSession().setAttribute("user", user)
            );
            var saved = new org.springframework.security.web.savedrequest.HttpSessionRequestCache()
                    .getRequest(request, response);
            response.sendRedirect(saved != null ? saved.getRedirectUrl() : "/home");
        };
    }

    /**
     * Seed an admin account on startup if none exists (H2 is in-memory,
     * so the database is empty on every restart).
     */
    @Bean
    public CommandLineRunner seedAdminUser(PasswordEncoder encoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                com.phishguard.model.User admin = new com.phishguard.model.User();
                admin.setUsername("admin");
                admin.setEmail("admin@phishguard.local");
                admin.setPasswordHash(encoder.encode("admin123"));
                admin.setRole("ADMIN");
                userRepository.save(admin);
                System.out.println("[PhishGuard] Admin user seeded (admin / admin123)");
            }
        };
    }
}

