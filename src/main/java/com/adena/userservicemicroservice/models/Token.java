package com.adena.userservicemicroservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity

public class Token extends BaseModel{

    private String token;
    @ManyToOne
    private Users user;
    private Date expireAt;

}
