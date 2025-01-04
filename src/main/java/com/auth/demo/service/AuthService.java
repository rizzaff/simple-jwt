package com.auth.demo.service;

import com.auth.demo.model.AuthRequest;
import com.auth.demo.model.LoginRequest;
import com.auth.demo.model.ResponseService;
import com.auth.demo.security.JwtUtil;
import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final JwtUtil jwtUtil;
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final Gson gson = new Gson();

    public AuthService(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public ResponseService auth(AuthRequest authRequest){
        logger.info("[AuthController] Incoming POST /auth/token");

        try {
            String json = gson.toJson(authRequest);

            logger.info("[AuthController] request: " + json);
            if ("user".equals(authRequest.getUsername()) && "password".equals(authRequest.getPassword())) {
                String token = jwtUtil.generateToken(authRequest.getUsername(), authRequest.getUserId(), authRequest.getRole());
                logger.info("[AuthController] Token generated: " + token);

                logger.info("[AuthController] Outgoing POST /auth/token");
                logger.info("[AuthService] Generating token for user: user with request ID: 1234");
                logger.info("[AuthService] Token generated: " + token);

                return ResponseService.builder()
                        .responseCode("200")
                        .responseData(token)
                        .responseDesc("Token Generated")
                        .build();
            } else {
                logger.info("[AuthController] Invalid credentials");
                return ResponseService.builder()
                        .responseCode("500")
                        .responseDesc("Internal Server Error")
                        .build();
            }

        } catch (Exception e) {
            logger.error("[AuthService] Error: " + e);
            throw new RuntimeException("Invalid credentials");
        }
    }

    public ResponseService login(LoginRequest loginRequest) {
        logger.info("[AuthController] Incoming POST /auth/login");
        try {
            if(jwtUtil.validateToken(loginRequest.getToken(), loginRequest.getUsername())){

                logger.info("[AuthController] Login Request");

                String json = gson.toJson(loginRequest);

                logger.info("[AuthController] Response: " + json);

                Claims claims = jwtUtil.extractAllClaims(loginRequest.getToken());
                Map<String, Object> resp = new HashMap<>();
                resp.put("Username", claims.getSubject()); // Add user ID
                resp.put("UserID", claims.get("userId"));
                resp.put("Role", claims.get("role"));
                resp.put("token", loginRequest.getToken());
                resp.put("requestId", claims.get("requestId"));
                json = gson.toJson(resp);

                logger.info("[AuthController] Response: " + json);

                logger.info("[AuthController] Outgoing POST /auth/login");
                return ResponseService.builder()
                        .responseCode("200")
                        .responseData(resp)
                        .responseDesc("Login Successful")
                        .build();
            } else {
                logger.info("[AuthController] Invalid Token");
                return ResponseService.builder()
                        .responseCode("500")
                        .responseDesc("Internal Server Error")
                        .build();
            }
        } catch (Exception e) {
            logger.error("[AuthController] Error: " + e);
            throw new RuntimeException("Invalid Token");
        }

    }
}
