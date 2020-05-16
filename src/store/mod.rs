pub mod memory;

use crate::domain::user::User;
use crate::domain::client::Client;

pub trait UserStore {
    fn get(&self, key: &str) -> Option<User>;
}

pub trait ClientStore {
    fn get(&self, key: &str) -> Option<Client>;
}