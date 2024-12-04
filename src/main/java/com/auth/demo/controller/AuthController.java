package com.auth.demo.controller;

import com.auth.demo.model.AuthRequest;
import com.auth.demo.model.LoginRequest;
import com.auth.demo.model.ResponseService;
import com.auth.demo.security.JwtUtil;
import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final Gson gson = new Gson();

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/token")
    public String login(@RequestBody AuthRequest authRequest) {
        logger.info("[AuthController] Incoming POST /auth/token");
        String json = gson.toJson(authRequest);

        logger.info("[AuthController] request: " + json);
        if ("user".equals(authRequest.getUsername()) && "password".equals(authRequest.getPassword())) {
            String token = jwtUtil.generateToken(authRequest.getUsername(), authRequest.getUserId(), authRequest.getRole());
            logger.info("[AuthController] Token generated: " + token);
            logger.info("[AuthController] Outgoing POST /auth/token");
            return token;
        } else {
            logger.info("[AuthController] Invalid credentials");
            throw new RuntimeException("Invalid credentials");
        }
    }

    @PostMapping("/login")
    public ResponseService login(@RequestBody LoginRequest loginRequest) {
        logger.info("[AuthController] Incoming POST /auth/login");

        String json = gson.toJson(loginRequest);

        logger.info("[AuthController] request: " + json);
        if(jwtUtil.validateToken(loginRequest.getToken(), loginRequest.getUsername())){
            logger.info("[AuthController] Login Successful");

            Claims claims = jwtUtil.extractAllClaims(loginRequest.getToken());
            Map<String, Object> resp = new HashMap<>();
            resp.put("Username", claims.getSubject()); // Add user ID
            resp.put("UserID", claims.get("userId"));
            resp.put("Role", claims.get("role"));
            resp.put("token", loginRequest.getToken());

            ResponseService responseService = new ResponseService();
            responseService.setMessage("Login Successful");
            responseService.setCode("200");
            responseService.setData(resp);

            json = gson.toJson(responseService);

            logger.info("[AuthController] Response: " + json);
            logger.info("[AuthController] Outgoing POST /auth/login");
            return responseService;
        } else {
            logger.info("[AuthController] Invalid Token");
            throw new RuntimeException("Invalid Token");
        }
    }
}

