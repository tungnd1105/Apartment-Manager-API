package poly.com.api;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import poly.com.security.payload.LoginRequest;
import poly.com.security.services.LoginService;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/authencation/account")
public class LoginRestController {

    @Autowired
    private LoginService loginService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) throws Exception {
        return loginService.login(loginRequest);
    }


}
