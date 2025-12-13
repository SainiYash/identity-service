package com.portfolio.auth.identity_service.service;

/*
   1. VALIDATION: Check if user already exists
   2. SECURITY: Hash the password (never store plain text)
   3. BUSINESS RULES: Set proper defaults (role=USER, enabled=false)
   4. PERSISTENCE: Save to database
   5. RESPONSE: Return appropriate message

 */

import com.portfolio.auth.identity_service.dto.RegisterRequest;
import com.portfolio.auth.identity_service.dto.UserResponse;
import com.portfolio.auth.identity_service.entity.User;
import com.portfolio.auth.identity_service.exception.EmailAlreadyExistsException;
import com.portfolio.auth.identity_service.exception.InvalidOtpException;
import com.portfolio.auth.identity_service.exception.ResourceNotFoundException;
import com.portfolio.auth.identity_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;                  // encapsulates OTP generation + storage (Redis) + email send
  //  private final JwtService jwtService;                  // encapsulates JWT creation & validation
  //  private final RefreshTokenService refreshTokenService; // handles refresh token storage/rotation in Redis


    @Transactional
    public UserResponse register(RegisterRequest req){

        // Normalize inputs

        String email = req.getEmail().trim().toLowerCase();
        String name = req.getName().trim() ;
        String number = req.getPhoneNumber()== null ? null : req.getPhoneNumber().trim();

        // 1) Business validation: duplicate email

        if(userRepository.existsByEmail(email)){
            throw new EmailAlreadyExistsException("Email already registered: " + email);
        }
        // 2) Security: hash password

        String hashed = passwordEncoder.encode(req.getPassword());

        // 3) Business defaults: role & enabled=false until verification

        User user = User.builder()
                .name(name)
                .email(email)
                .passwordHash(hashed)
                .phoneNumber(number)
                .role(User.Role.USER)
                .enabled(false)
                .createdAt(LocalDateTime.now())
                .build();

        // 4) Persistence

        User saved = userRepository.save(user);

        // 5) Post-save: create OTP and send verification asynchronously
        // OTP stored in Redis with TTL (e.g., 10 minutes)
        try {
            System.out.println("🚀 Calling OTP service for: " + saved.getEmail());
            otpService.createAndQueueOtpForEmail(saved.getEmail());
        } catch (Exception e) {
            e.printStackTrace();  // show full email/redis errors
            throw e;
        }

        // 6) Map to safe response

        return UserResponse.builder()
                .id(saved.getId())
                .name(saved.getName())
                .email(saved.getEmail())
                .phoneNumber(saved.getPhoneNumber())
                .role(saved.getRole().name())
                .enabled(saved.isEnabled())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    @Transactional
    public void verifyEmailOtp(String email, String otpCode) {

        boolean isValid = otpService.verifyOtp(email, otpCode);

        if (!isValid) {
            throw new InvalidOtpException("Invalid or expired OTP");
        }

        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setEnabled(true);

        userRepository.save(user);
    }

    @Transactional
    public void resendEmailOtp(String emailRaw) {

        String email = emailRaw.trim().toLowerCase(Locale.ROOT);

        // 1) Check user exists
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        // 2) (Optional) If already verified, don't resend
        if (user.isEnabled()) {
            throw new IllegalStateException("User is already verified. OTP resend not allowed.");
        }

        // 3) Re-create OTP and send it
        System.out.println("🔁 Resending OTP for: " + email);
        otpService.createAndQueueOtpForEmail(email);
    }





}
