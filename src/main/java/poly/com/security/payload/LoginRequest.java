package poly.com.security.payload;


import lombok.Data;
import poly.com.entity.Role;

import javax.validation.constraints.NotBlank;
import java.util.HashSet;
import java.util.Set;

@Data
public class LoginRequest {

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    private Set<Role> role = new HashSet<>();
}
