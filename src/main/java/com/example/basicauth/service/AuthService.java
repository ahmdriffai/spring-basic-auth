package com.example.basicauth.service;

import com.example.basicauth.payload.request.AuthLoginRequest;
import com.example.basicauth.payload.request.AuthRegisterRequest;
import com.example.basicauth.payload.response.AuthResponse;
import org.springframework.http.ResponseCookie;

public interface AuthService {
    AuthResponse login(AuthLoginRequest request);
    AuthResponse register(AuthRegisterRequest request);
    ResponseCookie logout();
}
