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

use serde::de::Deserialize as _;
use serde::de::Visitor;
use serde::Deserializer;

#[allow(clippy::unnecessary_wraps)]
pub fn deserialise_empty_as_none<'de, D: Deserializer<'de>>(
    value: D,
) -> Result<Option<String>, D::Error> {
    struct OptionVisitor {
        marker: std::marker::PhantomData<String>,
    }

    impl<'de> Visitor<'de> for OptionVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("option")
        }

        #[inline]
        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        #[inline]
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            String::deserialize(deserializer).map(Some)
        }

        #[inline]
        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        #[doc(hidden)]
        fn __private_visit_untagged_option<D>(self, deserializer: D) -> Result<Self::Value, ()>
        where
            D: Deserializer<'de>,
        {
            Ok(String::deserialize(deserializer).ok())
        }
    }
    let mut result = value
        .deserialize_option(OptionVisitor {
            marker: std::marker::PhantomData,
        })
        .ok()
        .flatten();
    if let Some(ref content) = result {
        if content.is_empty() {
            result = None;
        }
    }
    Ok(result)
}
