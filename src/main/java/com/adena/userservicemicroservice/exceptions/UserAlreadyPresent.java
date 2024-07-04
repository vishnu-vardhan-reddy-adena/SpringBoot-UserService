package com.adena.userservicemicroservice.exceptions;

public class UserAlreadyPresent extends Exception {
    public UserAlreadyPresent(String message) {
        super(message);
    }
}
