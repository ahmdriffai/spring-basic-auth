package com.example.basicauth.payload.response;

import com.example.basicauth.entity.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.http.ResponseCookie;

import java.util.List;

public class AuthResponse {
    String username;
    String email;
    List<Role> roles;
    @JsonIgnore
    ResponseCookie responseCookie;

    public AuthResponse() {
    }

    public AuthResponse(String username, String email, List<Role> roles) {
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public ResponseCookie getResponseCookie() {
        return responseCookie;
    }

    public void setResponseCookie(ResponseCookie responseCookie) {
        this.responseCookie = responseCookie;
    }
}
