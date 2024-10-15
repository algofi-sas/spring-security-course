package fr.algofi.hnn.springsecuritytuto.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.Principal;

@Getter
@AllArgsConstructor
public class SimplePrincipal implements Principal {
    private String username;

    @Override
    public String getName() {
        return this.username;
    }
}
