package com.example.hybridauth.controller;

import com.example.hybridauth.dto.*;
import com.example.hybridauth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    /**
     * Step 1: 초기 로그인 (Session 기반)
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        log.info("Login attempt for user: {}", request.getUsername());

        LoginResponse response = authService.login(request, httpRequest);
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    /**
     * Step 2: JWT 토큰 발급 (Session으로 인증된 사용자)
     * POST /api/auth/session/tokens
     */
    @PostMapping("/session/tokens")
    public ResponseEntity<ApiResponse<TokenResponse>> issueTokens(HttpServletRequest request) {
        log.info("Token issuance requested");

        TokenResponse response = authService.issueTokens(request);
        return ResponseEntity.ok(ApiResponse.success("Tokens issued successfully", response));
    }

    /**
     * Step 3: Access Token 갱신
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refreshToken(
            @RequestBody RefreshTokenRequest request) {

        log.info("Token refresh requested");

        TokenResponse response = authService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", response));
    }

    /**
     * 로그아웃 (Session과 Refresh Token 무효화)
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            HttpServletRequest request,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;
        authService.logout(request, refreshToken);

        return ResponseEntity.ok(ApiResponse.success("Logout successful", null));
    }

    /**
     * 회원가입
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt for user: {}", request.getUsername());

        authService.register(request.getUsername(), request.getEmail(), request.getPassword());

        return ResponseEntity.ok(ApiResponse.success("Registration successful", "User created"));
    }
}

// RefreshTokenRequest DTO 추가
class RefreshTokenRequest {
    private String refreshToken;

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}

// RegisterRequest DTO 추가
class RegisterRequest {
    private String username;
    private String email;
    private String password;

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
}