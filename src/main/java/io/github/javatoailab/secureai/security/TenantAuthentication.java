package io.github.javatoailab.secureai.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

public final class TenantAuthentication extends AbstractAuthenticationToken {

    private final TenantPrincipal tenant;

    public TenantAuthentication(TenantPrincipal tenant) {
        super(authorities(tenant));
        this.tenant = tenant;
        setAuthenticated(true);
    }

    private static List<SimpleGrantedAuthority> authorities(TenantPrincipal tenant) {
        List<SimpleGrantedAuthority> list = new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_TENANT"));
        if (tenant.admin()) {
            list.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        return list;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public TenantPrincipal getPrincipal() {
        return tenant;
    }
}
