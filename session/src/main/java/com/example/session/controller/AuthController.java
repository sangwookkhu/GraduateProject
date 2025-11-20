package com.example.session.controller;

import com.example.session.dto.UserRegistrationDto;
import com.example.session.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                       @RequestParam(required = false) String logout,
                       Model model) {
        if (error != null) {
            model.addAttribute("error", "아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        if (logout != null) {
            model.addAttribute("message", "로그아웃되었습니다.");
        }
        return "login";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(UserRegistrationDto registrationDto, Model model) {
        try {
            userService.registerUser(registrationDto);
            model.addAttribute("message", "회원가입이 완료되었습니다. 로그인해주세요.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    @GetMapping("/home")
    public String home(Model model) {
        return "home";
    }
}

