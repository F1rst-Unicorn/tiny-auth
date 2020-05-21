use crate::domain::user::User;
use crate::store::UserStore;
use crate::store::ClientStore;
use crate::domain::client::Client;

pub struct MemoryUserStore {}

impl UserStore for MemoryUserStore {
    fn get(&self, key: &str) -> Option<User> {
        Some(User {
            name: key.to_string(),
            password: "".to_string(),
        })
    }
}

pub struct MemoryClientStore {}

impl ClientStore for MemoryClientStore {
    fn get(&self, key: &str) -> Option<Client> {
        Some(Client {
            client_id: key.to_string(),
            redirect_uris: vec!("http://localhost/client".to_string()),
        })
    }
}