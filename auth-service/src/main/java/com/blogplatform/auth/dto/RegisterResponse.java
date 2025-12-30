package com.blogplatform.auth.dto;

public class RegisterResponse {

    private String userId;
    private String message;

    public RegisterResponse(String userId, String message) {
        this.userId = userId;
        this.message = message;
    }

    public String getUserId() { return userId; }
    public String getMessage() { return message; }
}

