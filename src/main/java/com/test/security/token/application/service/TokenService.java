package com.test.security.token.application.service;

import com.test.security.user.domain.User;

public interface TokenService {
    void saveToken(User user, String jwtToken);
}
