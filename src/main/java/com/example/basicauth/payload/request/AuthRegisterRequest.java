package com.example.basicauth.payload.request;

import javax.validation.constraints.NotBlank;
import java.util.List;


public class AuthRegisterRequest {

    @NotBlank
    String username;
    @NotBlank
    String email;
    @NotBlank
    String password;
    List<String> roles;

    public AuthRegisterRequest() {
    }

    public AuthRegisterRequest(String username, String email, String password, List<String> roles) {
        this.username = username;
        this.email = email;
        this.password = password;
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
