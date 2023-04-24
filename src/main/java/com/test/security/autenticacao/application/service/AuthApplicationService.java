package com.test.security.autenticacao.application.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.security.autenticacao.application.api.AuthentificationRequest;
import com.test.security.autenticacao.application.api.AuthentificationResponse;
import com.test.security.autenticacao.application.api.RegisterRequest;
import com.test.security.service.JwtService;
import com.test.security.token.Token;
import com.test.security.token.TokenRepository;
import com.test.security.token.TokenType;
import com.test.security.user.application.repository.UserRepository;
import com.test.security.user.domain.User;
import com.test.security.user.infra.UserSpringDataJPARepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthApplicationService implements AuthService {

    private final UserSpringDataJPARepository userSpringDataJPARepository;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthentificationResponse register(RegisterRequest request) {
        log.info("[inicia]  AuthApplicationService - register");
        User user = userRepository.salva(new User(request));
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateToken(user);
        saveUserToken(user, jwtToken);
        log.info("[fim]  AuthApplicationService - register");
        return AuthentificationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public AuthentificationResponse authenticate(AuthentificationRequest request) {
        log.info("[inicia]  AuthApplicationService - authenticate");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userSpringDataJPARepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        revokeAllUserTokens(user,jwtToken);
        saveUserToken(user, jwtToken);
        log.info("[fim]  AuthApplicationService - authenticate");
        return AuthentificationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void saveUserToken2_true(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(true)
                .revoked(true)
                .build();
        tokenRepository.save(token);
    }
    private void revokeAllUserTokens(User user,String jwtToken) {
        log.info("[inicia]  AuthApplicationService - revokeAllUserTokens");
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
            token.setToken("jwtToken");
        });
        tokenRepository.saveAll(validUserTokens);
        log.info("[fim]  AuthApplicationService - revokeAllUserTokens");
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response
    ) throws IOException {
        log.info("[inicia]  AuthApplicationService - refreshToken");
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userSpringDataJPARepository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user,refreshToken);
                saveUserToken(user, accessToken);
                var authResponse = AuthentificationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
        log.info("[fim]  AuthApplicationService - refreshToken");
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("[inicia]  AuthApplicationService - logout");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        log.info("[fim]  AuthApplicationService - logout");
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
