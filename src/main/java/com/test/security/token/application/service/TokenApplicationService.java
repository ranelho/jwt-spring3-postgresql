package com.test.security.token.application.service;

import com.test.security.token.application.repository.TokenRepository;
import com.test.security.token.domain.Token;
import com.test.security.user.domain.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Log4j2
public class TokenApplicationService implements TokenService {
    private final TokenRepository tokenRepository;
    @Override
    public void saveToken(User user, String jwtToken) {
        log.info("[inicia] TokenApplicationService - saveToken");
        tokenRepository.salva(new Token(user, jwtToken));
        log.info("[finaliza] TokenApplicationService - saveToken");
    }
}
