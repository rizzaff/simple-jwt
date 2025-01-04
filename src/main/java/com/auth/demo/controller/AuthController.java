package com.auth.demo.controller;

import com.auth.demo.model.AuthRequest;
import com.auth.demo.model.LoginRequest;
import com.auth.demo.model.ResponseService;
import com.auth.demo.security.JwtUtil;
import com.auth.demo.service.AuthService;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final Gson gson = new Gson();
    private final AuthService authService;

    public AuthController(JwtUtil jwtUtil, AuthService authService) {
        this.jwtUtil = jwtUtil;
        this.authService = authService;
    }

    @PostMapping("/token")
    public ResponseService token(@RequestBody AuthRequest authRequest) {
       return authService.auth(authRequest);
    }

    @PostMapping("/login")
    public ResponseService login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }
}

