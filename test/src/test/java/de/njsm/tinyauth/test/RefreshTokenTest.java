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

import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.runtime.Browser;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.Matchers.equalTo;

public interface RefreshTokenTest extends AuthorizationCodeGadgets, ClientSetter {

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-refresh-token")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-refresh-token")
    default void authenticateAndTryRefreshToken(Browser browser) throws Exception {
        Client client1 = getClient();
        Client client2 = Clients.getClientForTokenSwitchAttack();

        setClient(client1);
        String authCode = fetchAuthCode(browser, getScopes());
        OidcToken firstRefreshToken = verifyTokensFromAuthorizationCodeReturningRefreshToken(getScopes(), authCode);
        verifyTokensFromResponse(getScopes(), tokenEndpoint().requestWithRefreshToken(getClient(), firstRefreshToken, getScopes()));

        setClient(client2);
        browser.resetCookies();

        authCode = fetchAuthCode(browser, getScopes());
        OidcToken secondRefreshToken = verifyTokensFromAuthorizationCodeReturningRefreshToken(getScopes(), authCode);
        verifyTokensFromResponse(getScopes(), tokenEndpoint().requestWithRefreshToken(getClient(), secondRefreshToken, getScopes()));

        setClient(client1);
        tokenEndpoint().request(getClient(), secondRefreshToken, getScopes())
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid refresh token"));
    }
}
