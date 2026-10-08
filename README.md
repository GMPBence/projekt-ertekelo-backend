# Projektértékelő backend

Axum + MySQL API for the `projekt-ertekelo` frontend.

## Local setup

1. Create a MySQL database and user (for example `projekt_ertekelo`).
2. Copy `.env.example` to `.env`; configure `DATABASE_URL` and a random `JWT_SECRET` of at least 32 characters.
3. For password recovery, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM`. Without SMTP, the rest of the API starts normally, but recovery requests for existing accounts return `503`.
4. Start the API with `cargo run`. SQLx applies migrations from `migrations/` at startup.
5. From `projekt-ertekelo`, run `npm run dev`. Set `VITE_API_URL` if the API is not at `http://localhost:8080/api/v1`.

## API

- `POST /api/v1/auth/register` — `{ "email", "username", "password" }`
- `POST /api/v1/auth/login` — `{ "email", "password" }`; returns a bearer token and public user data
- `POST /api/v1/auth/recover` — `{ "email" }`; emails a nine-digit, 15-minute code (five attempts)
- `POST /api/v1/auth/recover/complete` — `{ "email", "token", "password" }`; consumes the code
- `GET /api/v1/projects` — authenticated project list with the current user's evaluation
- `POST /api/v1/projects` — authenticated `{ "title", "authors", "description", "website_url" }`
- `GET /api/v1/projects/{id}` — authenticated project details and the current user's evaluation
- `POST /api/v1/projects/{id}/evaluations` — authenticated `{ "grade", "theme", "design", "animations", "javascript", "feedback", "published" }`
- `GET /health` — liveness check

Passwords use bcrypt. Bearer tokens expire after 24 hours. Configure `CORS_ORIGINS` as a comma-separated list of exact frontend origins for your deployment.
