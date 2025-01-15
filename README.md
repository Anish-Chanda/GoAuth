# GoAuth
Welcome to the GoAuth project! 🚀 This open-source authentication package for Go aims to provide a flexible, developer-friendly authentication solution that doesn't rely on third-party services, giving you full control over your user data. Although there's no working version yet, here’s what you can expect from the project and how you can get involved.

> 🚧 The project is still in development, and there's no working version yet, but we would love your input as we build it! You can watch the repository to stay updated, fork it to experiment, or open issues for discussions.

## Current Development
In the current v0.1.0 version, we have implemented support for email/password authentication, SQLite3 database integration, JWT access and refresh tokens, and Argon2 password hashing.

### Implemented API Endpoints
#### POST /signup
Creates a new user account with email/password authentication.
Expected Request:
```
{
    "email": "user@example.com",
    "password": "securepassword123"
}
```
#### POST /login
Authenticates a user and returns access/refresh tokens.
Expected Request:
```
{
    "email": "user@example.com",
    "password": "securepassword123"
}
```
#### POST /refresh
Issues a new access token using a valid refresh token.
Expected Request:
```
{
    "refresh_token": "your.refresh.token"
}
```
### Configuration
---
The `Config` Struct allows customization of 

- JWT Secret and token lifetimes
- Password policies (length, Hash algorithm)
- Hasher Settings
    - (Argon2 - time cost, salt & key length, memory cost, parallelism)
- Database type

### Security
Security is a top priority for GoAuth. I have implemented a few measures to ensure the safety of user data, following OWASP guidelines for email validation, password storage, and other security practices. 

> **Suggestions from security experts are much appreciated!** We are always looking to improve our security measures and would love to hear your recommendations.

## 🚀 Features (Planned)
- **Auth Methods**: Support for email/password (Implemented), OAuth2, 2FA, phone, magic links, etc. Also, have password reset and account recovery flows, which are customizable.
- **Database Flexibility**: Ability to use the same database your project is using, like PostgreSQL, MySQL, and MongoDB
- **Frontend Components**: Pre-built login components for popular frontend frameworks (e.g., React, Vue, Svelte) which you can copy pasta 🍝.
- **Admin Endpoints**: Include admin functionalities for user management.
- **Future Plans**: Possibly adding a web dashboard template for managing users. Multi-tenancy. Generating and managing API keys for end users?

## Roadmap
- V0.1.0 - Email Password Auth, JWT access and refresh tokens, SQLite3 DB Support
- V0.2.0 - Oauth2 support (google, github, ...), PostgreSQL DB Support, Logging System.

## 🧠 How You Can Help

The project is in its early stages, and your feedback is crucial to shaping its direction. Here's how you can contribute:
- Suggest Features: Is there something you think is missing in current auth packages?
- Contribute Code: Feel free to fork the repository and submit a pull request.

