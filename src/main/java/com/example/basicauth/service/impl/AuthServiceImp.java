package com.example.basicauth.service.impl;

import com.example.basicauth.entity.ERole;
import com.example.basicauth.entity.Role;
import com.example.basicauth.entity.User;
import com.example.basicauth.exception.AuthException;
import com.example.basicauth.payload.request.AuthLoginRequest;
import com.example.basicauth.payload.request.AuthRegisterRequest;
import com.example.basicauth.payload.response.AuthResponse;
import com.example.basicauth.repository.RoleRepository;
import com.example.basicauth.repository.UserRepository;
import com.example.basicauth.security.jwt.JwtUtils;
import com.example.basicauth.security.service.UserDetailsImpl;
import com.example.basicauth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class AuthServiceImp implements AuthService {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public AuthResponse login(AuthLoginRequest request) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        // Set Cockie
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        httpHeaders.set(HttpHeaders.SET_COOKIE, jwtCookie.toString());


        AuthResponse authResponse = new AuthResponse(userDetails.getUsername(), userDetails.getEmail(), userDetails.getRoles());
        authResponse.setResponseCookie(jwtCookie);

        return authResponse;
    }

    @Override
    public AuthResponse register(AuthRegisterRequest request) {
        // Cek apakah username sudah terdafrtar?
        if (userRepository.existsByUsername(request.getUsername())){
            throw new AuthException("Username tidak tersedia");
        }

        // Cek apakah email sudah terdaftar?
        if (userRepository.existsByEmail(request.getEmail())){
            throw new AuthException("Email sudah terdaftar");
        }

        // Membuat user akun
        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        List<String> strRole = request.getRoles();
        List<Role> roles = new ArrayList<>();

        if (strRole == null){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new AuthException("Role ridak ditemukan"));
            roles.add(userRole);
        }else {
            strRole.forEach(role -> {
                switch (role){
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new AuthException("Role tidak ditemukan"));
                        roles.add(adminRole);
                        break;
                    case "dosen":
                        Role dosenRole = roleRepository.findByName(ERole.ROLE_DOSEN)
                                .orElseThrow(() -> new AuthException("Role tidak ditemukan"));
                        roles.add(dosenRole);
                        break;
                    case "mahasiswa":
                        Role mahasiswaRole = roleRepository.findByName(ERole.ROLE_MAHASISWA)
                                .orElseThrow(() -> new AuthException("Role tidak ditemukan"));
                        roles.add(mahasiswaRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new AuthException("Role tidak ditemukan"));
                        roles.add(userRole);
                }
            });
        }

        // add role to db
        user.setRoles(roles);
        userRepository.save(user);

        return new AuthResponse(user.getUsername(), user.getEmail(), roles);


    }

    @Override
    public ResponseCookie logout() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();

        return cookie;
    }
}
