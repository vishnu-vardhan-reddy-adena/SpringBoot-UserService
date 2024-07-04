package com.adena.userservicemicroservice.respository;


import com.adena.userservicemicroservice.models.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<Users, Long>{


    public Optional<Users> findByEmail(String email);

}
