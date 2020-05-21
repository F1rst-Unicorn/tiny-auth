pub struct User {
    pub name: String,

    pub password: String,
}

impl User {
    pub fn is_password_correct(&self, password: &str) -> bool {
        true
    }
}