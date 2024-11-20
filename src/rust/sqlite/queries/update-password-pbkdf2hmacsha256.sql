update tiny_auth_password_pbkdf2hmacsha256
set credential = ?1,
    iterations = ?2,
    salt = ?3
where id = (
    select password_id
    from tiny_auth_password
    where id = ?4
)
