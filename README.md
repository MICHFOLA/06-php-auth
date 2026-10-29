# SWD Auth

A PHP 8 authentication example for XAMPP and MySQL.

## Setup

1. Start Apache and MySQL in the XAMPP Control Panel.
2. Import `database/schema.sql` in phpMyAdmin or the MySQL command line. It creates the `swd_auth` database, `users`, and `login_attempts` tables.
3. Configure the database through `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` environment variables if the XAMPP defaults (`127.0.0.1`, `3306`, `swd_auth`, `root`, blank password) do not apply.
4. The default `APP_ENV` is `production`. For local HTTP development, set `APP_ENV=development` in Apache's environment; this permits HTTP and displays PHP errors. Do not use that setting on a public server.
5. To grant the first administrator role, run from a terminal:

   ```text
   C:\xampp\php\php.exe C:\xampp\htdocs\swd\06-php-auth\promote-admin.php me@example.com
   ```

For an existing database from the earlier stages, apply any schema migration that has not already been run. In particular, `database/migrate_stage2.sql` adds the role and last-login columns.

## Security features

- Passwords use PHP's `password_hash()` / `password_verify()` APIs with `PASSWORD_DEFAULT`; login upgrades hashes when needed.
- Prepared PDO statements are used for database operations, with exceptions enabled and emulated prepares disabled.
- Sessions use strict mode, HTTP-only and SameSite=Lax cookies, and session-ID rotation on authentication and password changes. Production requires HTTPS and uses Secure session cookies; HSTS is sent on HTTPS requests.
- CSRF tokens protect state-changing forms. Logout only accepts POST.
- Login failures are tracked by email and client IP. Five failures in a rolling 15-minute window temporarily block that email or IP; a successful login clears matching attempts.
- Authenticated pages enforce login and a 30-minute idle timeout. Admin pages enforce the `admin` role server-side.
- Intended post-login destinations are validated as local relative paths to avoid open redirects.
- Output rendered in HTML is escaped. Responses include `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
- Profile updates validate name and email and rely on the unique email constraint to prevent duplicates. Password changes require the current password and rotate the session ID.

Production deployment must terminate HTTPS correctly and keep `APP_ENV` unset or set to `production`. Configure PHP/Apache error logging rather than displaying diagnostic errors to visitors.
