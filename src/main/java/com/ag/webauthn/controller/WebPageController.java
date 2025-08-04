package com.ag.webauthn.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebPageController {

    @GetMapping("/register")
    public String showRegistrationPage() {
        return "registration"; // Loads src/main/resources/templates/registration.html
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login"; // Loads src/main/resources/templates/login.html
    }
}