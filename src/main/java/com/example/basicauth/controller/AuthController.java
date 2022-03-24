package com.example.basicauth.controller;

import com.example.basicauth.payload.request.AuthLoginRequest;
import com.example.basicauth.payload.request.AuthRegisterRequest;
import com.example.basicauth.payload.response.AuthResponse;
import com.example.basicauth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthService authService;

    @PostMapping(
            value = "/login",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest request, HttpServletResponse response){
        AuthLoginRequest loginRequest = new AuthLoginRequest(
                request.getUsername(),
                request.getPassword()
        );


        AuthResponse authResponse = authService.login(request);


        response.addHeader(HttpHeaders.SET_COOKIE, authResponse.getResponseCookie().toString());

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping(
            value = "/register",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<AuthResponse> register(@RequestBody @Valid AuthRegisterRequest request){
        AuthRegisterRequest registerRequest = new AuthRegisterRequest(
                request.getUsername(),
                request.getEmail(),
                request.getPassword(),
                request.getRoles()
        );

        AuthResponse response = authService.register(registerRequest);
        return ResponseEntity.ok(response);

    }
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie responseCookie = authService.logout();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, responseCookie.toString()).body("Succes Logout");
    }
}
