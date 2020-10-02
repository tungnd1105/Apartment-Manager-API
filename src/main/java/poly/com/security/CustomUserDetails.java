package poly.com.security;


import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import poly.com.entity.Employee;
import poly.com.entity.Role;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private static final long serialVersionUID = 2432178622826014669L;
    Employee employee;


    @Override /*-------------- get user role ---------------- */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> grantedAuthority = new HashSet<>();
        Set<Role> roles = employee.getRoles();
        for (Role role : roles) {
            grantedAuthority.add(new SimpleGrantedAuthority(role.getName() + ""));
        }
        return grantedAuthority;
    }

    @Override
    public String getPassword() {
        return employee.getPassword();
    }

    @Override
    public String getUsername() {
        return employee.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
