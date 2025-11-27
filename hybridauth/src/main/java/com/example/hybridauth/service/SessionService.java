package com.example.hybridauth.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class SessionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String SESSION_PREFIX = "spring:session:sessions:";

    public SessionService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void createSession(HttpServletRequest request, String username, Long userId) {
        HttpSession session = request.getSession(true);

        session.setAttribute("username", username);
        session.setAttribute("userId", userId);
        session.setAttribute("loginTime", LocalDateTime.now().toString());
        session.setAttribute("userAgent", request.getHeader("User-Agent"));
        session.setAttribute("ipAddress", getClientIP(request));

        // Redis에 추가 메타데이터 저장
//        String sessionKey = SESSION_PREFIX + session.getId();
//        Map<String, Object> sessionData = new HashMap<>();
//        sessionData.put("username", username);
//        sessionData.put("userId", userId.toString());  // ← Long을 String으로 변환!
//        sessionData.put("loginTime", LocalDateTime.now().toString());
//        sessionData.put("lastAccessTime", LocalDateTime.now().toString());
//
//        redisTemplate.opsForHash().putAll(sessionKey, sessionData);
//        redisTemplate.expire(sessionKey, 30, TimeUnit.MINUTES);

        log.info("Session created for user: {} with session ID: {}", username, session.getId());
    }

    public void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            String username = (String) session.getAttribute("username");

            // Redis에서 세션 데이터 삭제
            String sessionKey = SESSION_PREFIX + sessionId;
            redisTemplate.delete(sessionKey);

            // 세션 무효화
            session.invalidate();

            log.info("Session invalidated for user: {} with session ID: {}", username, sessionId);
        }
    }

    public boolean validateSession(HttpSession session) {
        if (session == null) {
            return false;
        }

        String username = (String) session.getAttribute("username");
        if (username == null) {
            return false;
        }

        // IP와 User-Agent 검증 (세션 하이재킹 방지)
        String storedIp = (String) session.getAttribute("ipAddress");
        String storedUserAgent = (String) session.getAttribute("userAgent");

        // 실제 프로덕션에서는 현재 요청의 IP/User-Agent와 비교
        // 여기서는 단순히 존재 여부만 확인

        return storedIp != null && storedUserAgent != null;
    }

    public void updateSessionActivity(HttpSession session) {
        if (session != null) {
            String sessionKey = SESSION_PREFIX + session.getId();
            redisTemplate.opsForHash().put(sessionKey, "lastAccessTime", LocalDateTime.now().toString());
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}