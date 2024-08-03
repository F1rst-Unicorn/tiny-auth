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

import de.njsm.tinyauth.test.data.Scope;
import de.njsm.tinyauth.test.data.User;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Profile extends Scope {

    private static final Profile INSTANCE = new Profile();

    public static Profile get() {
        return INSTANCE;
    }

    @Override
    protected void verifyClaimsFor(User user, Map<String, Object> claims) {
        assertEquals(user.getName(), claims.get("name"));
        assertEquals(user.getFamilyName(), claims.get("family_name"));
        assertEquals(user.getGivenName(), claims.get("given_name"));
        assertEquals(user.getMiddleName(), claims.get("middle_name"));
        assertEquals(user.getNickname(), claims.get("nickname"));
        assertEquals(user.getPreferredUsername(), claims.get("preferred_username"));
        assertEquals(user.getProfile(), claims.get("profile"));
        assertEquals(user.getPicture(), claims.get("picture"));
        assertEquals(user.getWebsite(), claims.get("website"));
        assertEquals(user.getGender(), claims.get("gender"));
        assertEquals(user.getBirthday(), claims.get("birthdate"));
        assertEquals(user.getZoneinfo(), claims.get("zoneinfo"));
        assertEquals(user.getLocale(), claims.get("locale"));
        assertEquals((long) user.getUpdatedAt(), claims.get("updated_at"));
    }
}
