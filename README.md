# Identity Service

A production-ready authentication and authorization service built with Spring Boot, Spring Security, JWT, Redis, and MySQL, providing secure user authentication, email verification, password recovery, and role-based access control through RESTful APIs.

---

## Overview

Identity Service is a production-ready authentication and authorization backend that centralizes user identity management for modern applications. It provides secure REST APIs for user registration, email verification, JWT-based authentication, password recovery, and role-based authorization. Built using Spring Boot following layered architecture and REST best practices, the service is designed to integrate seamlessly with monolithic applications and microservice ecosystems.

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


The project follows a layered architecture to separate business logic, security, persistence, and API handling, making the codebase modular and maintainable.

---

## Authentication Workflow

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

---

## REST API Endpoints

 Live Demo 
   
   https://drive.google.com/file/d/1MoK7cclnTR5zL7w76hKkYVE0Me8jKBDx/view?usp=sharing

| Method | Endpoint                                 | Description                        |
| :----: | ---------------------------------------- | ---------------------------------- |
|  POST  | /api/auth/register                       | Register a new user                |
|  POST  | /api/auth/verify-otp                     | Verify email using OTP             |
|  POST  | /api/auth/login                          | Authenticate user and generate JWT |
|  POST  | /api/auth/forgot-password                | Generate password reset OTP        |
|  POST  | /api/auth/forgot-password/verify-otp     | Verify password reset OTP          |
|  POST  | /api/auth/forgot-password/reset-password | Reset user password                |

---


