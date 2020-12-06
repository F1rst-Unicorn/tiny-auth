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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class Profile extends Scope {

    private static final Profile INSTANCE = new Profile();

    public static Profile get() {
        return INSTANCE;
    }

    @Override
    public void verifyClaimsFor(User user, JWTClaimsSet claims) {
        try {
            assertEquals(user.getName(), claims.getStringClaim("name"));
            assertEquals(user.getFamilyName(), claims.getStringClaim("family_name"));
            assertEquals(user.getGivenName(), claims.getStringClaim("given_name"));
            assertEquals(user.getMiddleName(), claims.getStringClaim("middle_name"));
            assertEquals(user.getNickname(), claims.getStringClaim("nickname"));
            assertEquals(user.getPreferredUsername(), claims.getStringClaim("preferred_username"));
            assertEquals(user.getProfile(), claims.getStringClaim("profile"));
            assertEquals(user.getPicture(), claims.getStringClaim("picture"));
            assertEquals(user.getWebsite(), claims.getStringClaim("website"));
            assertEquals(user.getGender(), claims.getStringClaim("gender"));
            assertEquals(user.getBirthday(), claims.getStringClaim("birthdate"));
            assertEquals(user.getZoneinfo(), claims.getStringClaim("zoneinfo"));
            assertEquals(user.getLocale(), claims.getStringClaim("locale"));
            assertEquals(user.getUpdatedAt(), claims.getLongClaim("updated_at"));
        } catch (ParseException e) {
            fail(e);
        }
    }
}
