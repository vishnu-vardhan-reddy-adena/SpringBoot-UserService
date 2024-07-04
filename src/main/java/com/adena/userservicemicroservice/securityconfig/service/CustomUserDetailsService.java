package com.adena.userservicemicroservice.securityconfig.service;


import com.adena.userservicemicroservice.models.Users;
import com.adena.userservicemicroservice.respository.UserRepository;
import com.adena.userservicemicroservice.securityconfig.models.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Users> usersOptional = userRepository.findByEmail(username);
        if (usersOptional.isEmpty()) {
            throw new UsernameNotFoundException("user with "+username+ " not found");
        }
        Users users = usersOptional.get();
        UserDetails userDetails = new CustomUserDetails(users);

        return userDetails;
    }
}
