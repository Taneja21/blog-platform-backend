package com.blogplatform.auth.dto;

public class LoginResponse {

    private String accessToken;
    private String tokenType = "Bearer";

    public LoginResponse(String accessToken){
        this.accessToken=accessToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }
}
