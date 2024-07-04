package com.adena.userservicemicroservice.securityconfig.repository;

import java.util.Optional;


import com.adena.userservicemicroservice.securityconfig.models.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
