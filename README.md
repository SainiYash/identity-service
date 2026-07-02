# Identity Service

> A production-ready authentication and authorization microservice built with Spring Boot.

---

## Overview

Identity Service is responsible for managing user authentication and authorization in a secure and scalable manner. It provides REST APIs for user registration, 
email verification, login, password recovery, and JWT-based authentication. The service is designed to be integrated into larger applications or microservice 
ecosystems as a centralized identity provider.

---

---

## Features

- Secure user registration with password encryption using BCrypt
- Email verification using One-Time Password (OTP)
- JWT-based stateless authentication
- Role-Based Access Control (RBAC)
- Secure login with Spring Security
- Forgot password and password reset workflow
- Redis-backed OTP storage with automatic expiration (TTL)
- Global exception handling with standardised API responses
- Request validation using Jakarta Validation
- Asynchronous email delivery using Spring Mail
- RESTful API design following layered architecture
- OpenAPI (Swagger) documentation
- Docker and Docker Compose support

---

## Tech Stack

| Category | Technology |
|-----------|------------|
| Language | Java 17 |
| Framework | Spring Boot 3 |
| Security | Spring Security, JWT |
| Database | MySQL |
| Cache | Redis |
| ORM | Spring Data JPA (Hibernate) |
| Email | Spring Mail |
| API Documentation | OpenAPI (Swagger) |
| Build Tool | Maven |
| Containerization | Docker, Docker Compose |
| Validation | Jakarta Validation |

---

## Project Structure

```
src
├── config
├── controller
├── dto
├── entity
├── exception
├── repository
├── security
├── service
└── resources
```

The project follows a layered architecture to separate business logic, security, persistence, and API handling, making the codebase modular and maintainable.

---

## Authentication Workflow

```text
User
   │
   ▼
Register
   │
   ▼
Password Encrypted (BCrypt)
   │
   ▼
User Stored in MySQL
   │
   ▼
OTP Generated
   │
   ▼
OTP Stored in Redis (TTL)
   │
   ▼
OTP Sent via Email
   │
   ▼
Email Verification
   │
   ▼
Account Activated
   │
   ▼
Login
   │
   ▼
JWT Access Token Generated
   │
   ▼
Access Protected APIs
```

