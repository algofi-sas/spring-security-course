package fr.algofi.hnn.springsecuritytuto.config;

import fr.algofi.hnn.springsecuritytuto.filter.JWTGeneratorFilter;
import fr.algofi.hnn.springsecuritytuto.filter.JWTValidatorFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableMethodSecurity
public class AppSecurityConfig {
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring().requestMatchers("/h2-console/**");
    }

    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        // use HTTPS
//        http.requiresChannel(rm -> rm.anyRequest().requiresSecure());

        // concurrent session control
//        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidsession")
//                .maximumSessions(1).maxSessionsPreventsLogin(true));

        http.csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(new JWTValidatorFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTGeneratorFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests((requests) ->
                requests.requestMatchers(HttpMethod.POST, "/users").access(
                            new WebExpressionAuthorizationManager("hasAuthority('WRITE_USER') && hasRole('ADMIN')"))
                        .requestMatchers(HttpMethod.GET, "/users", "/users/{userId}").hasAnyAuthority("WRITE_USER", "READ_USER")
                        .requestMatchers(HttpMethod.POST, "/topics").hasAuthority("WRITE_TOPIC")
                        .requestMatchers(HttpMethod.POST, "/topics/{topicId}/opinions").hasAuthority("WRITE_OPINION")
                        .requestMatchers(HttpMethod.GET, "/topics", "/topics/{topicId}").permitAll()
                        .requestMatchers(HttpMethod.GET, "/error").permitAll());
        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

}
