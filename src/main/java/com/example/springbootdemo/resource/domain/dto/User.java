package com.example.springbootdemo.resource.domain.dto;

import lombok.Data;

@Data
public class User {
    private Integer id;

    private String username;

    private String password;
}
