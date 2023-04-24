package com.test.security.autenticacao.application.service;

import com.test.security.autenticacao.application.api.AuthentificationRequest;
import com.test.security.autenticacao.application.api.AuthentificationResponse;
import com.test.security.autenticacao.application.api.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthService {
    AuthentificationResponse register(RegisterRequest request);
    AuthentificationResponse authenticate(AuthentificationRequest request);
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
    void logout(HttpServletRequest request, HttpServletResponse response);
}
