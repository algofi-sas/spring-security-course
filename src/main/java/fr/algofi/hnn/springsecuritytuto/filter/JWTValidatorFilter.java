package fr.algofi.hnn.springsecuritytuto.filter;

import fr.algofi.hnn.springsecuritytuto.util.AppConstant;
import fr.algofi.hnn.springsecuritytuto.util.SimplePrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWTValidatorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwt = request.getHeader(AppConstant.AUTHORIZATION_HEADER);
        if (jwt != null && jwt.contains("Bearer")) {
            try {
                String token = jwt.substring(7);
                SecretKey secretKey = Keys.hmacShaKeyFor(AppConstant.JWT_SECRET.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
                String username = claims.get("username", String.class);
                String authorities = claims.get("authorities", String.class);
                Authentication authentication = new UsernamePasswordAuthenticationToken(new SimplePrincipal(username), null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                throw new BadCredentialsException(e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String jwt = request.getHeader(AppConstant.AUTHORIZATION_HEADER);
        if (jwt == null || jwt.contains("Basic")) {
            return true;
        }
        return super.shouldNotFilter(request);
    }
}
