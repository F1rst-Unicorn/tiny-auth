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

package de.njsm.tinyauth.test.data.scopes;

import com.nimbusds.jwt.JWTClaimsSet;
import de.njsm.tinyauth.test.data.Scope;
import de.njsm.tinyauth.test.data.User;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

public class Email extends Scope {

    private static final Email INSTANCE = new Email();

    public static Email get() {
        return INSTANCE;
    }

    @Override
    public void verifyClaimsFor(User user, JWTClaimsSet claims) {
        try {
            assertEquals(user.getEmail(), claims.getStringClaim("email"));
            assertTrue(claims.getBooleanClaim("email_verified"), "email is not marked verified");
        } catch (ParseException e) {
            fail(e);
        }
    }
}
