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

import de.njsm.tinyauth.test.oidc.Identifiers;
import de.njsm.tinyauth.test.repository.Users;
import de.njsm.tinyauth.test.runtime.Browser;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class Tests extends AuthorizationCodeTest {

    @Test
    void testFailingLoginRateLimits(Browser browser) {
        user = Users.getSecondRateLimitTestUser();
        String wrongPassword = "wrong password";

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUsername(user.getUsername())
                .withPassword(wrongPassword)
                .loginWithError()
                .assertPasswordWrongError(2)
                .withUsername(user.getUsername())
                .withPassword(wrongPassword)
                .loginWithError()
                .assertPasswordWrongError(1)
                .withUsername(user.getUsername())
                .withPassword(wrongPassword)
                .loginWithErrorAndRedirect();

        HttpUrl oidcRedirect = getLastOidcRedirect(browser);

        assertUrlParameter(oidcRedirect, ERROR, ACCESS_DENIED);
        assertUrlParameter(oidcRedirect, ERROR_DESCRIPTION, "user failed to authenticate");
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .loginWithError()
                .assertRateLimitedError();
    }

    @Test
    void testNonGrantedScopeIsWithdrawn(Browser browser) throws Exception {
        scopes = Set.of("openid", "email", "phone");
        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .toggleScope("phone")
                .confirm();

        String authorizationCode = assertOnRedirect(browser);
        fetchTokensAndVerifyBasics(Set.of("openid", "email"), tokenEndpoint().request(client, authorizationCode));
    }

    @Override
    Set<Identifiers.ResponseType> getResponseTypes() {
        return Set.of(Identifiers.ResponseType.CODE);
    }
}
