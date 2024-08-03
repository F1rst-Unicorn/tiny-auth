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

package de.njsm.tinyauth.test.data;

import com.nimbusds.jwt.JWTClaimsSet;
import io.restassured.path.json.JsonPath;

import java.util.Map;

import static de.njsm.tinyauth.test.oidc.TokenAsserter.convertTokenClaims;
import static de.njsm.tinyauth.test.oidc.TokenAsserter.convertUserinfoClaims;

public abstract class Scope {

    public void verifyClaimsFor(User user, JWTClaimsSet claims) {
        verifyClaimsFor(user, convertTokenClaims(claims));
    }

    public void verifyClaimsFor(User user, JsonPath claims) {
        verifyClaimsFor(user, convertUserinfoClaims(claims));
    }

    protected abstract void verifyClaimsFor(User user, Map<String, Object> claims);
}
