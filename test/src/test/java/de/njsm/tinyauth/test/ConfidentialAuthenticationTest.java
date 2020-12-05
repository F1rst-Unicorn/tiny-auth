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
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.repository.Users;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfidentialAuthenticationTest extends TinyAuthBrowserTest {

    @Test
    void simple(Browser browser) throws Exception {
        User user = Users.getUser();
        Client client = Clients.getConfidentialClient();
        Set<String> scopes = Set.of("openid");

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .confirm();

        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertTrue(oidcRedirect.getQueryStringParameters().containsEntry(STATE, getStateParameter()));
        assertTrue(oidcRedirect.getQueryStringParameters().getValues(ERROR).isEmpty());

        String authorizationCode = oidcRedirect.getFirstQueryStringParameter(ResponseType.CODE.get());
        assertThat(authorizationCode.length(), is(greaterThanOrEqualTo(16)));

        JsonPath extractor = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authorizationCode)
                .body(SCOPE, equalTo(String.join(" ", scopes)))
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalTo(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        tokenAsserter().verifyAccessToken(extractor.getString(ACCESS_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyAccessToken(extractor.getString(ID_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyRefreshToken(extractor.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
    }
}
