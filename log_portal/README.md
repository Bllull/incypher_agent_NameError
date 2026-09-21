# Log portal

This is a separate Flask application for PythonAnywhere. It receives
structured logs from an authorized remote CTF-agent container and serves them
to a local pull client. Received content is treated only as data.

## PythonAnywhere setup

1. Upload this `log_portal` directory.
2. Create a Flask web app and point its WSGI file at `app`:

   ```python
   import sys
   sys.path.insert(0, "/home/<username>/log_portal")
   from app import app as application
   ```

3. Set `LOG_PORTAL_TOKEN` and `LOG_PORTAL_DB` in the PythonAnywhere web-app
   environment. Use an absolute database path in the user's writable home
   directory.
4. Reload the web app. PythonAnywhere exposes the application through its
   assigned HTTPS URL; it does not generally expose arbitrary listener ports.

The remote image uses `LOG_PORTAL_URL`, for example
`https://<username>.pythonanywhere.com`, and the matching `LOG_PORTAL_TOKEN`.

## API

- `POST /api/logs`: `{ "source": "agent", "entries": [...] }`
- `GET /api/logs?after=<id>&limit=<n>`: returns unseen entries and `next_after`
- `GET /healthz`: unauthenticated health check

Both API routes require `Authorization: Bearer <LOG_PORTAL_TOKEN>`.
