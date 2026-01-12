package com.portfolio.auth.identity_service.service;


import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private final StringRedisTemplate redisTemplate;
    private final MailService mailService;

    private final int OTP_EXPIRY_MINUTES = 10;

    @Override
    public void createAndQueueOtpForEmail(String email, OtpPurpose purpose) {

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        // 1) Generate 6-digit OTP
        String otp = String.format("%06d", new SecureRandom().nextInt(1_000_000));

        String redisKey = buildRedisKey(normalizedEmail, purpose);

        // 2) Store OTP in Redis (with TTL)
        redisTemplate.opsForValue()
                .set(redisKey, otp, OTP_EXPIRY_MINUTES, TimeUnit.MINUTES);

        // 3) Send via email (REAL email)
        mailService.sendOtpEmail(normalizedEmail, otp);

        // Still print for debugging (optional)
        System.out.println("OTP for " + normalizedEmail + " is: " + otp);
    }

    @Override
    public boolean verifyOtp(String email, String otpCode, OtpPurpose purpose) {

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        String redisKey = buildRedisKey(normalizedEmail, purpose);

        String storedOtp = redisTemplate.opsForValue().get(redisKey);

        if (storedOtp == null) {
            return false;
        }

        boolean match = storedOtp.equals(otpCode);

        if (match) {
            redisTemplate.delete(redisKey);
        }

        return match;
    }

    @Override
    public void markOtpVerified(String email, OtpPurpose purpose) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        String key = "otp_verified:" + purpose.name() + ":" + normalizedEmail;

        redisTemplate.opsForValue().set(key, "true", 10, TimeUnit.MINUTES);
    }

    @Override
    public boolean isOtpVerified(String email, OtpPurpose purpose) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        String key = "otp_verified:" + purpose.name() + ":" + normalizedEmail;

        return "true".equals(redisTemplate.opsForValue().get(key));
    }


    private String buildRedisKey(String email, OtpPurpose purpose) {
        return "otp:" + purpose.name() + ":" + email;
    }
}
