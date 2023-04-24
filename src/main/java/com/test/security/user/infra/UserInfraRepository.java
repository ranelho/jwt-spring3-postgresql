package com.test.security.user.infra;

import com.test.security.user.application.repository.UserRepository;
import com.test.security.user.domain.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
@Log4j2
public class UserInfraRepository implements UserRepository {
    private final UserSpringDataJPARepository userSpringDataJPARepository;
    @Override
    public User salva(User user) {
        log.info("[inicia] UserInfraRepository - salva");
        userSpringDataJPARepository.save(user);
        log.info("[finaliza] UserInfraRepository - salva");
        return user;
    }
}
