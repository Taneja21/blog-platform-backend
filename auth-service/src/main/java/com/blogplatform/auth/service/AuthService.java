package com.blogplatform.auth.service;

import com.blogplatform.auth.dto.RegisterRequest;
import com.blogplatform.auth.entity.UserEntity;
import com.blogplatform.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserEntity register(RegisterRequest request){
        if(userRepository.existsByEmail(request.getEmail())){
            throw new IllegalArgumentException("Email already in use");
        }
        if(userRepository.existsByUsername(request.getUsername())){
            throw new IllegalArgumentException("Username already in use");
        }

        UserEntity user = new UserEntity();
        user.setEmail(request.getEmail());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        return userRepository.save(user);
    }


    public UserEntity login(String email, String rawPassword){
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if(!passwordEncoder.matches(rawPassword, user.getPassword())){
            throw new IllegalArgumentException("Invalid username or password");
        }
        return user;
    }
}
