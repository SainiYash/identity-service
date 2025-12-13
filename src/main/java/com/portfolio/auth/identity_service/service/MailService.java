package com.portfolio.auth.identity_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public void sendOtpEmail(String toEmail, String otpCode) {
        String subject = "Your OTP Verification Code";

        String text = """
                Hello,

                Your OTP verification code is: %s

                This code will expire in 10 minutes.

                If you did not request this, you can ignore this email.
                """.formatted(otpCode);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(text);

        try {
            log.info("Attempting to send email from {} to {}", fromEmail, toEmail);
            log.info("Email subject: {}", subject);

            mailSender.send(message);
            log.info("✓ OTP email sent successfully to {}", toEmail);

        } catch (MailAuthenticationException e) {
            log.error("✗ Mail authentication failed for {}", fromEmail, e);
            log.error("Check SMTP username/password and app permissions");
        } catch (MailSendException e) {
            log.error("✗ Failed to send mail to {}", toEmail, e);
            log.error("Check recipient email format and SMTP configuration");
        } catch (Exception e) {
            log.error("✗ Unexpected error sending email to {}", toEmail, e);
        }
    }
}