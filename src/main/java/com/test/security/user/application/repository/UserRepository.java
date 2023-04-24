package com.test.security.user.application.repository;

import com.test.security.user.domain.User;

import java.util.Optional;

public interface UserRepository {
    User salva(User user);
    Optional<User> findByEmail(String email);
}
