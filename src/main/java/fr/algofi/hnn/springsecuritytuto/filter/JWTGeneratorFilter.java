package fr.algofi.hnn.springsecuritytuto.filter;

import fr.algofi.hnn.springsecuritytuto.util.AppConstant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNullApi;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

public class JWTGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            SecretKey secretKey = Keys.hmacShaKeyFor(AppConstant.JWT_SECRET.getBytes(StandardCharsets.UTF_8));
            String jwt = Jwts.builder().issuer("Spring-Secu-Tuto").subject("JWT")
                    .claim("username", authentication.getName())
                    .claim("authorities", authentication.getAuthorities()
                        .stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                    .issuedAt(new Date())
                    .expiration(new Date((new Date()).getTime() + 3600000))
                    .signWith(secretKey).compact();
            response.setHeader(AppConstant.AUTHORIZATION_HEADER, jwt);
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String jwt = request.getHeader(AppConstant.AUTHORIZATION_HEADER);
        if (jwt != null && jwt.contains("Bearer")) {
            return true;
        }
        return super.shouldNotFilter(request);
    }
}
