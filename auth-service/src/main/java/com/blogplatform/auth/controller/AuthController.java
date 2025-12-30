package com.blogplatform.auth.controller;

import com.blogplatform.auth.dto.LoginRequest;
import com.blogplatform.auth.dto.LoginResponse;
import com.blogplatform.auth.dto.RegisterRequest;
import com.blogplatform.auth.dto.RegisterResponse;
import com.blogplatform.auth.entity.UserEntity;
import com.blogplatform.auth.security.JwtAuthenticationFilter;
import com.blogplatform.auth.security.JwtUtil;
import com.blogplatform.auth.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log =
            LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService,
    JwtUtil jwtUtil){
        this.authService = authService;
        this.jwtUtil = jwtUtil;
    }



    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request){
        UserEntity user = authService.register(request);


        return ResponseEntity.status(HttpStatus.CREATED).body(new RegisterResponse(
                user.getId(),
                "User registered successfully"
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request
            ){
        UserEntity user = authService.login(request.getEmail(), request.getPassword());

        log.info("Logged In");

        String token = jwtUtil.generateToken(
                user.getId(),
                user.getEmail(),
                user.getPassword()
        );

        return ResponseEntity.ok(new LoginResponse(token));
    }



}
