package com.portfolio.auth.identity_service.controller;

import com.portfolio.auth.identity_service.dto.*;
import com.portfolio.auth.identity_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest req) {
        UserResponse resp = authService.register(req);
        URI location = URI.create("/api/users/" + resp.getId());
        return ResponseEntity.created(location).body(resp);
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestBody VerifyOtpRequest req) {
        authService.verifyEmailOtp(req.getEmail(), req.getOtpCode());
        return ResponseEntity.ok("Email verified successfully!");
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<String> resendOtp(@Valid @RequestBody ResendOtpRequest req) {
        authService.resendEmailOtp(req.getEmail());
        return ResponseEntity.ok("OTP resent successfully to " + req.getEmail());
    }

    @PostMapping("/forgot-Password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest req){
        authService.forgotPassword(req.getEmail());
        return ResponseEntity.ok(
                "If the email is registered and verified, an OTP has been sent."
        );
    }
}
