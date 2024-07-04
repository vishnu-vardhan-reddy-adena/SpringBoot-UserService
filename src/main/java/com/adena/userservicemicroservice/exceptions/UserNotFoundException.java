package com.adena.userservicemicroservice.exceptions;

public class UserNotFoundException extends Exception{
    public UserNotFoundException(String Message){
        super(Message);
    }
}
