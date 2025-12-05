package com.portfolio.auth.identity_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private final StringRedisTemplate redisTemplate;

    private final int OTP_EXPIRY_MINUTES = 10;

    @Override
    public void createAndQueueOtpForEmail(String email) {

        // 1) Generate 6-digit OTP
        String otp = String.format("%06d", new Random().nextInt(999999));

        String redisKey = "otp:" + email;

        // 2) Store OTP in Redis (with TTL)
        redisTemplate.opsForValue().set(redisKey, otp, OTP_EXPIRY_MINUTES, TimeUnit.MINUTES);

        // 3) Send via email (stub)
        System.out.println("OTP for " + email + " is: " + otp);
    }

    @Override
    public boolean verifyOtp(String email, String otpCode) {

        String redisKey = "otp:" + email;

        // Get stored OTP
        String storedOtp = redisTemplate.opsForValue().get(redisKey);

        if (storedOtp == null) {
            return false; // expired or nonexistent
        }

        // Compare case-sensitive
        boolean match = storedOtp.equals(otpCode);

        if (match) {
            // delete OTP from Redis after successful verification
            redisTemplate.delete(redisKey);
        }

        return match;
    }
}
