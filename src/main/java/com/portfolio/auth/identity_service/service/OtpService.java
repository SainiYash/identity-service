package com.portfolio.auth.identity_service.service;

public interface OtpService {


    // Step 1: Create OTP and store in Redis
    void createAndQueueOtpForEmail(String email, OtpPurpose purpose);

    // Step 2: Validate OTP from Redis
    boolean verifyOtp(String email, String otpCode, OtpPurpose purpose);
}
