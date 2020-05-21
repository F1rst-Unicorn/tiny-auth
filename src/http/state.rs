use std::boxed::Box;
use tera::Tera;

use crate::store::ClientStore;
use crate::store::UserStore;

pub struct State {
    pub tera: Tera,

    pub client_store: Box<dyn ClientStore>,

    pub user_store: Box<dyn UserStore>,
}
