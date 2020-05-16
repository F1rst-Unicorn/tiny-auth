use std::boxed::Box;
use tera::Tera;

use crate::store::ClientStore;


pub struct State {
    pub tera: Tera,

    pub client_store: Box<dyn ClientStore>,
}
