package com.adena.userservicemicroservice.exceptions;

public class TokenInvalidException extends Exception{
    public TokenInvalidException(String message) {
        super(message);
    }
}
