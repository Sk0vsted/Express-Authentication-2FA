# What is this?
This is a secure Node.js web application built with Express, featuring authentication, two-factor authentication (2FA), and database interactions using SQLite. It combines a REST API with Pug templates for server-side rendering.

# Features

- User Authentication with JWT & Bcrypt

- Two-Factor Authentication (2FA) using Speakeasy & QR Codes

- Database Management with SQLite (better-sqlite3)

- Server-Rendered Views using Pug

- Secure Cookie-Based Authentication

- RESTful API Endpoints for user & grade management

# Tech Stack

- **Backend:** Node.js, Express

- **Database:** SQLite (better-sqlite3)

- **Authentication:** JWT, Bcrypt, Speakeasy (for 2FA)

- **Frontend:** Pug, CSS

- **Security:** Cookie-based JWT auth, environment variable-based secrets

# Installation

## Clone the repository
``git clone https://github.com/yourusername/express-authentication-2fa.git``

``cd express-authentication-2fa``

## Install dependencies
``npm install``

## Edit .env to configure your secret keys
``SECRET=yourKeyHere``

``SECRET_CRYPTO=yourCryptoKeyHere``

# Start the server
``npm test``

# API Endpoints

## Authentication
| Method | Endpoint           | Description          |
|--------|--------------------|----------------------|
| POST   | /users/register    | Register a new user  |
| POST   | /users/login       | User login with JWT  |
| GET    | /users/logout      | Logs the user out    |
| POST   | /users/enable-2fa  | Enables 2FA for user |
| POST   | /users/verify-2fa  | Verify 2FA OTP       |
| POST   | /users/disable-2fa | Disable 2FA          |

## User Management
| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | /users/profile        | Profile Page (Dashboard) |
| GET    | /users/courses-grades | View grades (admin/user) |
| POST   | /users/update-grade   | Admin updates grades     |

# License
**This project is open-source!** 

Feel free to contribute!

