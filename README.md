Name Katie
number 2023905318
## JWT signing secret

`JWT_SECRET` is required. For this lab, a long random secret is stored in the local `.env` file, which Git ignores. Docker Compose passes it to the web service, and the application has no default signing secret.

In production, load the signing secret from a secrets store and inject it into the service environment at runtime. Never commit the real secret value to source control.

