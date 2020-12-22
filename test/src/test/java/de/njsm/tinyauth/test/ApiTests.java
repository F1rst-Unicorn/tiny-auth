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
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ApiTests implements TinyAuthTest {

    private final Client client = Clients.getConfidentialClient();

    private final User user = Users.getUser();

    private final Set<String> scopes = Set.of("openid");

    @Test
    void testClientCredentialsGrant() throws Exception {
        JsonPath tokenResponse = tokenEndpoint().requestWithClientCredentials(client, scopes)
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        tokenAsserter().verifyAccessTokenWithoutNonce(tokenResponse.getString(ID_TOKEN), client, client);
    }

    @Test
    void testPasswordGrant() throws Exception {
        JsonPath tokenResponse = tokenEndpoint().requestWithPassword(client, user, scopes)
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        tokenAsserter().verifyAccessTokenWithoutNonce(tokenResponse.getString(ID_TOKEN), client, user);
    }

    @Test
    void passwordGrantIsRateLimited() {
        User user = Users.getRateLimitTestUser();
        String wrongPassword = "wrong-password";
        String errorDescription = "username or password wrong";
        int maxAllowed = 3;

        for (int i = 0; i < maxAllowed; i++) {
            tokenEndpoint().requestWithPassword(client, user, wrongPassword, scopes)
                    .statusCode(400)
                    .body(ERROR, equalTo(INVALID_GRANT))
                    .body(ERROR_DESCRIPTION, equalTo(errorDescription));
        }

        tokenEndpoint().requestWithPassword(client, user, scopes)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("rate limited"));
    }
}
