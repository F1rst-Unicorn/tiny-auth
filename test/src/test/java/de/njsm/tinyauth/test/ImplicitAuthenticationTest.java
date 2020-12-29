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

import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.oidc.Identifiers;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.runtime.Browser;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class ImplicitAuthenticationTest extends TinyAuthBrowserTest {

    @BeforeEach
    void setUp() {
        client = Clients.getPublicClient();
    }

    OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(client, getState(), scopes, getNonce(), additionalParameters)
                .withUser(user)
                .login()
                .confirm();

        return extractTokenFromRedirect(browser);
    }

    OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
        browser.startAuthentication(client, getState(), scopes, getNonce())
                .withUser(user)
                .login()
                .confirm();

        return extractTokenFromRedirect(browser);
    }

    OidcToken extractTokenFromRedirect(Browser browser) throws Exception {
        HttpUrl oidcRedirect = getLastOidcRedirect(browser);

        assertUrlParameter(oidcRedirect, EXPIRES_IN, "60");
        assertUrlParameter(oidcRedirect, TOKEN_TYPE, "bearer");
        assertUrlParameter(oidcRedirect, STATE, getState());

        List<String> errors = oidcRedirect.queryParameterValues(ERROR);
        assertTrue(errors.isEmpty(), "server returned error: " + String.join(" ", errors));

        OidcToken returnToken = null;
        if (getResponseTypes().contains(ResponseType.ID_TOKEN)) {
            returnToken = tokenAsserter().verifyAccessToken(oidcRedirect.queryParameter(Identifiers.ID_TOKEN), client, user, getNonce());
        }
        if (getResponseTypes().contains(ResponseType.TOKEN)) {
            returnToken = tokenAsserter().verifyAccessToken(oidcRedirect.queryParameter(ACCESS_TOKEN), client, user, getNonce());
        }

        return returnToken;
    }

    @Override
    protected HttpUrl getLastOidcRedirect(Browser browser) {
        HttpUrl oidcRedirect = HttpUrl.get(browser.getCurrentlUrl());
        oidcRedirect = oidcRedirect.newBuilder()
                .query(oidcRedirect.fragment())
                .build();
        return oidcRedirect;
    }
}
