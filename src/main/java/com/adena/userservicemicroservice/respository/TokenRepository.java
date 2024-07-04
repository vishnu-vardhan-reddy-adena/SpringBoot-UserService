package com.adena.userservicemicroservice.respository;


import com.adena.userservicemicroservice.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    public Token save(Token token);

     public Optional<Token> findTokenByTokenAndExpireAtGreaterThanAndDeleted(String token, Date expireAt, Boolean deleted);

}
