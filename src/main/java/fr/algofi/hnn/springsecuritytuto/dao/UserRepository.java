package fr.algofi.hnn.springsecuritytuto.dao;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findUserByEmail(String email);
}
