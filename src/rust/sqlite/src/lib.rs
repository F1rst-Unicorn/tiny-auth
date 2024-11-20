/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod auth_code_store;
mod begin_immediate;
mod client_store;
mod data_assembler;
mod error;
mod health;
pub mod inject;
mod password_store;
mod scope_store;
mod store;
#[cfg(test)]
pub mod test;
mod user_store;

pub use data_assembler::DataAssembler;
pub use data_assembler::QueryLoader;
