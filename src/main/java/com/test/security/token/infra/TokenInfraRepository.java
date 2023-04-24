package com.test.security.token.infra;

import com.test.security.token.application.repository.TokenRepository;
import com.test.security.token.domain.Token;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
@Log4j2
public class TokenInfraRepository implements TokenRepository {
    private final TokenSpringJPARepository tokenSpringJPARepository;

    @Override
    public void salva(Token token) {
        log.info("[inicia] TokenInfraRepository - salva ");
        tokenSpringJPARepository.save(token);
        log.info("[finaliza] TokenInfraRepository - salva");
    }
}
