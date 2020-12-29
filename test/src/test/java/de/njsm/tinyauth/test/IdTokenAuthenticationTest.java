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

package de.njsm.tinyauth.test;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.ResponseType;

public class IdTokenAuthenticationTest extends ImplicitAuthenticationTest implements ConformanceTest, MissingNonceFailureTest {

    @Override
    public Set<ResponseType> getResponseTypes() {
        return Set.of(ResponseType.ID_TOKEN);
    }
}
