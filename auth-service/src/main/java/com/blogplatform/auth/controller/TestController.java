package com.blogplatform.auth.controller;

import com.blogplatform.auth.security.JwtAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class TestController {

    private static final Logger log =
            LoggerFactory.getLogger(TestController.class);

    @GetMapping("/secure-test")
    public String secure(Authentication authentication){
        return "Authenticated user id = " + authentication.getPrincipal();
    }
}
