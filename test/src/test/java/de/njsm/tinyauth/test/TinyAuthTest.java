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

import de.njsm.tinyauth.test.repository.Endpoint;
import de.njsm.tinyauth.test.runtime.RestAssuredConfiguration;
import de.njsm.tinyauth.test.runtime.TokenEndpoint;
import de.njsm.tinyauth.test.runtime.UserinfoEndpoint;
import de.njsm.tinyauth.test.runtime.UutLifecycleManager;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(UutLifecycleManager.class)
@ExtendWith(RestAssuredConfiguration.class)
public interface TinyAuthTest {

    Endpoint endpoint();

    default TokenEndpoint tokenEndpoint() {
        return new TokenEndpoint(endpoint());
    }

    default UserinfoEndpoint userinfoEndpoint() {
        return new UserinfoEndpoint(endpoint());
    }
}
