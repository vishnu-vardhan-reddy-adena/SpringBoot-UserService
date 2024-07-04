package com.adena.userservicemicroservice.controllers;


import com.adena.userservicemicroservice.DTOs.LoginRequestDTO;
import com.adena.userservicemicroservice.DTOs.LogoutRequestDTO;
import com.adena.userservicemicroservice.DTOs.SignUpResponseDTO;
import com.adena.userservicemicroservice.DTOs.SignupRequestDTO;
import com.adena.userservicemicroservice.exceptions.TokenInvalidException;
import com.adena.userservicemicroservice.exceptions.UserAlreadyPresent;
import com.adena.userservicemicroservice.models.Token;
import com.adena.userservicemicroservice.models.Users;
import com.adena.userservicemicroservice.service.AuthService;
import com.adena.userservicemicroservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequestMapping("/public")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthService authService;
    @Autowired
    public UserController(UserService userService, AuthService authService) {
        this.userService = userService;
        this.authService = authService;
    }

    @PostMapping("/user/register")
    public Users signUp(@RequestBody SignupRequestDTO signupRequestDTO) throws UserAlreadyPresent {

        Users user = userService.signUp(signupRequestDTO.getName(), signupRequestDTO.getEmail(), signupRequestDTO.getPassword());
        SignUpResponseDTO signUpResponseDTO = SignUpResponseDTO.fromSignUpResponseDTO(user);
        return user;

    }

    @PostMapping("/user/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginRequest) throws Exception {

        String access_token = String.valueOf(authService.login(loginRequest));
        return ResponseEntity.ok(Map.of("access_token", access_token));
    }


    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody LogoutRequestDTO requestDTO) throws TokenInvalidException {

        Token token = userService.logout(requestDTO.getToken());
        ResponseEntity<String> responseEntity = new ResponseEntity<>(
                token.isDeleted()==true ?"Successfully logged out":"Invalid token",
                token.isDeleted()==true ? HttpStatus.OK : HttpStatus.INTERNAL_SERVER_ERROR
        );
        return responseEntity;
    }

    @GetMapping("/validate/{tokenValue}")
    public Token validateToken(@PathVariable String tokenValue) throws TokenInvalidException {
        Token token = userService.validateToken(tokenValue);
        //UserDTO userDTO = UserDTO.fromUser(token.getUser());
        return token;
    }


    @GetMapping("/hello")
    public String hello(){
        return "Hello World";
    }


}
