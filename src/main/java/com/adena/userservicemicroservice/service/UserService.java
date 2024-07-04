package com.adena.userservicemicroservice.service;


import com.adena.userservicemicroservice.DTOs.PasswordChangeDTO;
import com.adena.userservicemicroservice.DTOs.UserDTO;
import com.adena.userservicemicroservice.exceptions.InvalidPasswordException;
import com.adena.userservicemicroservice.exceptions.TokenInvalidException;
import com.adena.userservicemicroservice.exceptions.UserAlreadyPresent;
import com.adena.userservicemicroservice.exceptions.UserNotFoundException;
import com.adena.userservicemicroservice.models.Token;
import com.adena.userservicemicroservice.models.Users;
import com.adena.userservicemicroservice.respository.TokenRepository;
import com.adena.userservicemicroservice.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.text.ParseException;
import java.util.*;

@Service
public class UserService {


    private UserRepository userRepository;
    private BCryptPasswordEncoder encoder;
    private TokenRepository tokenRepository;

    @Autowired
    public  UserService(UserRepository userRepository, TokenRepository tokenRepository ,BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.tokenRepository = tokenRepository;

    }
    public Users signUp(String name, String email, String password) throws UserAlreadyPresent {
        Optional<Users> usersOptional = userRepository.findByEmail(email);
        if (usersOptional.isPresent()) {
            throw new UserAlreadyPresent("User already Present With this Email "+email);
        }

        Users user = new Users();
        user.setEmail(email);
        user.setEmail(email);
        user.setName(name);
        user.setHashedPassword(encoder.encode(password));
        Users savedUser =  userRepository.save(user);
        return savedUser;
    };

    public String login(String email, String password) throws UserNotFoundException, InvalidPasswordException {
        Optional<Users> usersOptional = userRepository.findByEmail(email);
        if (usersOptional.isEmpty()) {
            throw new UserNotFoundException("User Not found SignUp");
        }
        Users users = usersOptional.get();
        if (!encoder.matches(password, users.getHashedPassword())) {
            throw new InvalidPasswordException("Wrong Password");
        }

        String userId = String.valueOf(users.getId()); // Assuming Users has an getId() method

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("name", users.getName());
        claims.put("email", users.getEmail());


        // You can add other user information to the claims as needed

        return "";
    }

//    private Key getSignKey() {
//        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
//    }



    public Token logout(String token) throws TokenInvalidException {
        Optional<Token>optionalToken = tokenRepository.findTokenByTokenAndExpireAtGreaterThanAndDeleted(token,new Date(),false);
        if (optionalToken.isEmpty()) {
            throw new TokenInvalidException("Token is InValid");
        }
        Token tokens = optionalToken.get();
        tokens.setDeleted(true);
        Token savedToken = tokenRepository.save(tokens);
        return savedToken;
    }

    public  Token validateToken(String token) throws TokenInvalidException {
        Optional<Token> optionalToken = tokenRepository.findTokenByTokenAndExpireAtGreaterThanAndDeleted(token,new Date(),false);
        if (optionalToken.isEmpty()) {
            throw new TokenInvalidException("Token is InValid");
        }
        return optionalToken.get();
    }

    public  boolean changePassword(PasswordChangeDTO passwordValue) throws InvalidPasswordException {

        Optional<Users> usersOptional = userRepository.findByEmail(passwordValue.getEmail());
        if (usersOptional.isEmpty()) {
            throw new InvalidPasswordException("User Not found SignUp");
        }
        Users users = usersOptional.get();
        if (!encoder.matches(passwordValue.getNewPassword(), users.getHashedPassword()) && (Objects.equals(passwordValue.getNewPassword(), passwordValue.getConfirmPassword()))) {
            throw new InvalidPasswordException("Wrong Password");
        }
        users.setHashedPassword(encoder.encode(passwordValue.getNewPassword()));

        return true;
    }

//    public UserDTO getUser() throws UserNotFoundException, ParseException {
//            long userId = Long.parseLong(TokenUtils.getUserId());
//        if (userId <= 0){
//            throw new UserNotFoundException("User Not Found");
//        }
//        Users user = userRepository.findById(userId).get();
//        UserDTO userDTO = UserDTO.fromUser(user);
//        return userDTO;
//    }
}
