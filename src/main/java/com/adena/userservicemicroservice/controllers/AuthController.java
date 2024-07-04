package com.adena.userservicemicroservice.controllers;


import com.adena.userservicemicroservice.DTOs.LoginRequestDTO;
import com.adena.userservicemicroservice.DTOs.SignUpResponseDTO;
import com.adena.userservicemicroservice.DTOs.SignupRequestDTO;
import com.adena.userservicemicroservice.exceptions.UserAlreadyPresent;
import com.adena.userservicemicroservice.models.Users;
import com.adena.userservicemicroservice.service.AuthService;
import com.adena.userservicemicroservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    AuthService authService;


    private UserService userService;

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }

//    @GetMapping("/user")
//    public ResponseEntity<?> getUser(@RequestHeader("Authorization") String authHeader) throws UserNotFoundException, ParseException {
//        // Extract the token from the Authorization header
//        String token = authHeader.replace("Bearer ", "");
//
//        // Decode the JWT token to extract user details
//        Jwt decodedJwt = jwtDecoder.decode(token);
//        String userId = decodedJwt.getClaimAsString("userId");
//
//        // Fetch user details using the extracted userId
//        UserDTO user = userService.getUser();
//
//        if (user != null) {
//            return ResponseEntity.ok(user);
//        } else {
//            throw new com.adena.edhukanuserservice.exceptions.UserNotFoundException("User not found with ID: " + userId);
//        }
//    }

//    @PostMapping("/changePassword")
//    public String changePassword(@RequestBody PasswordChangeDTO passwordChangeDTO) throws InvalidPasswordException {
//        boolean response = userService.changePassword(passwordChangeDTO);
//        if (response)return "Successfully changed password";
//        else return "Invalid password";
//    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}

