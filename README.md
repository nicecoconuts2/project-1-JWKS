# Project 1: JWKS Server

This project implements a RESTful JWKS server using Flask. It provides public keys for verifying JSON Web Tokens (JWTs), includes key expiry for enhanced security, and handles authentication requests.

## Endpoints

- `GET /jwks`: Returns the JSON Web Key Set (JWKS).
- `POST /auth`: Issues a signed JWT. Use the query parameter `?expired=true` to receive a JWT signed with an expired key.

## Setup

1. Clone the repository.
2. Create a virtual environment and activate it.
3. Install the required packages:
   ```bash
   pip install -r requirements.txt