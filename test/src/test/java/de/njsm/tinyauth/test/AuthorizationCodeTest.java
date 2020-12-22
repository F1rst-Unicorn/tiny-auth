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
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.repository.Users;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import io.restassured.response.ValidatableResponse;
import okhttp3.HttpUrl;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthorizationCodeTest extends TinyAuthBrowserTest {

    User user = Users.getUser();

    Client client = Clients.getConfidentialClient();

    Set<String> scopes = Set.of("openid");

    OidcToken authenticate(Browser browser) throws Exception {
        return authenticate(browser, scopes);
    }

    String authenticateReturningAuthCode(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, scopes);
        verifyTokensFromAuthorizationCode(scopes, authorizationCode);
        return authorizationCode;
    }

    OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(client, getStateParameter(), scopes, getNonceParameter(), additionalParameters)
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect(browser);
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
        String authorizationCode = fetchAuthCode(browser, scopes);
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    String fetchAuthCode(Browser browser, Set<String> scopes) {
        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .confirm();

        return assertOnRedirect(browser);
    }

    OidcToken verifyTokensFromAuthorizationCode(Set<String> scopes, String authCode) throws Exception {
        return verifyTokensFromResponse(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authCode));
    }

    void verifyTokensFromAuthorizationCodeWithClientPost(Set<String> scopes, String authCode) throws Exception {
        verifyTokensFromResponse(scopes, tokenEndpoint().requestWithAuthorizationCodeAndClientSecretPost(client, authCode));
    }

    OidcToken verifyTokensFromAuthorizationCodeReturningRefreshToken(Set<String> scopes, String authCode) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authCode));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
        return tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
    }

    OidcToken verifyTokensFromResponse(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, response);
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
        return tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
    }

    JsonPath fetchTokensAndVerifyBasics(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = response
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user, getNonceParameter());
        return tokenResponse;
    }

    void assertAuthCodeIsRejected(String authorizationCode) {
        tokenEndpoint().request(client, authorizationCode)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid code"));
    }

    String assertOnRedirect(Browser browser) {
        HttpUrl oidcRedirect = getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());

        List<String> errors = oidcRedirect.queryParameterValues(ERROR);
        assertTrue(errors.isEmpty(), "server returned error: " + String.join(" ", errors));

        String authorizationCode = oidcRedirect.queryParameter(ResponseType.CODE.get());
        assertThat(authorizationCode.length(), is(greaterThanOrEqualTo(16)));
        return authorizationCode;
    }

    @Override
    Set<ResponseType> getResponseTypes() {
        return Set.of(ResponseType.CODE);
    }
}
