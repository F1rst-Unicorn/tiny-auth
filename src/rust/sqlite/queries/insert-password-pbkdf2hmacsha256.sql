insert into tiny_auth_password_pbkdf2hmacsha256 (credential, iterations, salt)
values (?1, ?2, ?3)
returning id