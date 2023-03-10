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

package de.njsm.tinyauth.test.repository;

import de.njsm.tinyauth.test.data.User;

public class Users {
    public static User getUser() {
        return new User("john",
                "password",
                "John Horatio Doe",
                "Doe",
                "John",
                "Horatio",
                "Jonny",
                "doej",
                "profiles.example/doej",
                ":-)",
                "profiles.example/doej/profile",
                "diverse",
                "1991-09-11",
                "Europe/Berlin",
                "en-US",
                1409,
                "john@test.example",
                "Main Street 14\n11111 Portland\n",
                "+123456789");
    }

    public static User getRateLimitTestUser() {
        return new User("password-rate-limit", "password");
    }

    public static User getSecondRateLimitTestUser() {
        return new User("password-rate-limit-2", "password");
    }
}
