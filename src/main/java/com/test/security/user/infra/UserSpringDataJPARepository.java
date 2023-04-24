package com.test.security.user.infra;

import com.test.security.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserSpringDataJPARepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
}
