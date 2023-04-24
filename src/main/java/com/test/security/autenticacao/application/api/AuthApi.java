package com.test.security.autenticacao.application.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RequestMapping("/v1/auth")
public interface AuthApi {

    @PostMapping("/register")
    @ResponseStatus(code = HttpStatus.CREATED)
    AuthentificationResponse register(@RequestBody RegisterRequest request );

    @PostMapping("/authenticate")
    @ResponseStatus(code = HttpStatus.OK)
    AuthentificationResponse authenticate(@RequestBody AuthentificationRequest request );

    @PostMapping("/refresh-token")
    @ResponseStatus(code = HttpStatus.OK)
    void refreshToken(HttpServletRequest request, HttpServletResponse response ) throws IOException;

    @GetMapping("/logout")
    @ResponseStatus(code = HttpStatus.OK)
    void logout(HttpServletRequest request, HttpServletResponse response ) throws IOException;

}
