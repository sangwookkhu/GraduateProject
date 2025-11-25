package com.example.hybridauth.service;

import com.example.hybridauth.domain.RefreshToken;
import com.example.hybridauth.domain.User;
import com.example.hybridauth.dto.LoginRequest;
import com.example.hybridauth.dto.LoginResponse;
import com.example.hybridauth.dto.TokenResponse;
import com.example.hybridauth.repository.RefreshTokenRepository;
import com.example.hybridauth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SessionService sessionService;

    /**
     * 1단계: Session 기반 초기 인증 (로그인)
     * - 사용자가 로그인하면 Session을 생성하여 초기 인증 수행
     * - Redis에 세션 정보 저장
     */
    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        // 사용자 인증
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // 마지막 로그인 시간 업데이트
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Session 생성 (Redis에 저장)
        sessionService.createSession(httpRequest, user.getUsername(), user.getId());

        HttpSession session = httpRequest.getSession();

        log.info("User {} logged in successfully with session ID: {}", user.getUsername(), session.getId());

        return LoginResponse.builder()
                .sessionId(session.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .message("Login successful. Use session for initial authentication.")
                .build();
    }

    /**
     * 2단계: JWT 토큰 발급
     * - Session으로 인증된 사용자가 API 호출을 위한 JWT 토큰 요청
     * - Access Token과 Refresh Token 모두 발급
     */
    @Transactional
    public TokenResponse issueTokens(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            throw new IllegalStateException("No active session found");
        }

        String username = (String) session.getAttribute("username");
        if (username == null) {
            throw new IllegalStateException("Invalid session");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Access Token 생성
        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());

        // Refresh Token 생성 및 저장
        String refreshTokenString = jwtService.generateRefreshToken(user.getUsername());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenString)
                .userId(user.getId())
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        refreshTokenRepository.save(refreshToken);

        log.info("JWT tokens issued for user: {}", username);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenString)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .build();
    }

    /**
     * 3단계: Refresh Token으로 Access Token 갱신
     */
    @Transactional
    public TokenResponse refreshAccessToken(String refreshTokenString) {
        // Refresh Token 검증
        if (!jwtService.validateToken(refreshTokenString)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenString)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        if (refreshToken.isRevoked()) {
            throw new IllegalArgumentException("Refresh token has been revoked");
        }

        if (refreshToken.isExpired()) {
            throw new IllegalArgumentException("Refresh token has expired");
        }

        User user = userRepository.findById(refreshToken.getUserId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // 새로운 Access Token 발급
        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());

        log.info("Access token refreshed for user: {}", user.getUsername());

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshTokenString) // 기존 Refresh Token 유지
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .build();
    }

    /**
     * 로그아웃: Session과 Refresh Token 모두 무효화
     */
    @Transactional
    public void logout(HttpServletRequest request, String refreshToken) {
        // Session 무효화
        sessionService.invalidateSession(request);

        // Refresh Token 무효화
        if (refreshToken != null) {
            refreshTokenRepository.findByToken(refreshToken)
                    .ifPresent(token -> {
                        token.setRevoked(true);
                        refreshTokenRepository.save(token);
                    });
        }

        log.info("User logged out successfully");
    }

    /**
     * 회원가입
     */
    @Transactional
    public User register(String username, String email, String password) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists");
        }

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role("ROLE_USER")
                .isEnabled(true)
                .build();

        return userRepository.save(user);
    }
}