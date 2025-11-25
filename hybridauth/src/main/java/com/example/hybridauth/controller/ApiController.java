package com.example.hybridauth.controller;

import com.example.hybridauth.dto.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class ApiController {

    /**
     * JWT 인증이 필요한 API 엔드포인트 예시
     * GET /api/v1/profile
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getProfile(Authentication authentication) {
        log.info("Profile requested by user: {}", authentication.getName());

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", authentication.getName());
        profile.put("authorities", authentication.getAuthorities());
        profile.put("timestamp", LocalDateTime.now());

        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", profile));
    }

    /**
     * JWT 인증이 필요한 API 엔드포인트 예시
     * GET /api/v1/data
     */
    @GetMapping("/data")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getData(Authentication authentication) {
        log.info("Data requested by user: {}", authentication.getName());

        Map<String, Object> data = new HashMap<>();
        data.put("message", "This is protected data");
        data.put("user", authentication.getName());
        data.put("timestamp", LocalDateTime.now());

        return ResponseEntity.ok(ApiResponse.success("Data retrieved", data));
    }
}