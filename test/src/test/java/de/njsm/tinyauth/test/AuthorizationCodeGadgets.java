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
import de.njsm.tinyauth.test.oidc.redirect.RedirectQueryExtractor;
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
import static org.junit.jupiter.api.Assertions.*;

public interface AuthorizationCodeGadgets extends Gadgets, RedirectQueryExtractor {

    @Override
    default OidcToken authenticate(Browser browser) throws Exception {
        return authenticate(browser, getScopes());
    }

    default String authenticateReturningAuthCode(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, getScopes());
        verifyTokensFromAuthorizationCode(getScopes(), authorizationCode);
        return authorizationCode;
    }

    default OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
        String authorizationCode = fetchAuthCode(browser, scopes);
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    default OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(getClient(), getState(), getScopes(), getNonce(), additionalParameters)
                .withUser(getUser())
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect(browser);
        return verifyTokensFromAuthorizationCode(getScopes(), authorizationCode);
    }

    default String fetchAuthCode(Browser browser, Set<String> scopes) throws Exception {
        browser.startAuthentication(getClient(), getState(), scopes, getNonce())
                .withUser(getUser())
                .login()
                .confirm();

        return assertOnRedirect(browser);
    }

    default String fetchAuthCode(Browser browser, Map<String, String> additionalParamters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(getClient(), getState(), getScopes(), getNonce(), additionalParamters)
                .withUser(getUser())
                .login()
                .confirm();

        return assertOnRedirect(browser);
    }

    default String assertOnRedirect(Browser browser) throws Exception {
        HttpUrl oidcRedirect = getLastOidcRedirect(browser);

        assertUrlParameter(oidcRedirect, STATE, getState());

        if (getResponseTypes().contains(ResponseType.ID_TOKEN)
                || getResponseTypes().contains(ResponseType.TOKEN)) {
            assertUrlParameter(oidcRedirect, EXPIRES_IN, "60");
            assertUrlParameter(oidcRedirect, TOKEN_TYPE, "bearer");
        }

        List<String> errors = oidcRedirect.queryParameterValues(ERROR);
        assertTrue(errors.isEmpty(), "server returned error: " + String.join(" ", errors));

        String authorizationCode = oidcRedirect.queryParameter(ResponseType.CODE.get());
        assertNotNull(authorizationCode);
        assertThat(authorizationCode.length(), is(greaterThanOrEqualTo(16)));

        if (getResponseTypes().contains(ResponseType.ID_TOKEN)) {
            tokenAsserter().verifyAccessToken(oidcRedirect.queryParameter(Identifiers.ID_TOKEN), getClient(), getUser());
        }
        if (getResponseTypes().contains(ResponseType.TOKEN)) {
            tokenAsserter().verifyAccessToken(oidcRedirect.queryParameter(ACCESS_TOKEN), getClient(), getUser());
        }

        return authorizationCode;
    }

    default OidcToken verifyTokensFromAuthorizationCode(Set<String> scopes, String authCode) throws Exception {
        return verifyTokensFromResponse(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(getClient(), authCode));
    }

    default void verifyTokensFromAuthorizationCodeWithClientPost(Set<String> scopes, String authCode) throws Exception {
        verifyTokensFromResponse(scopes, tokenEndpoint().requestWithAuthorizationCodeAndClientSecretPost(getClient(), authCode));
    }

    default OidcToken verifyTokensFromAuthorizationCodeReturningRefreshToken(Set<String> scopes, String authCode) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(getClient(), authCode));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), getClient(), getUser());
        return tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), getClient(), getUser(), scopes);
    }

    default OidcToken verifyTokensFromResponse(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, response);
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), getClient(), getUser(), scopes);
        return tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), getClient(), getUser());
    }

    default JsonPath fetchTokensAndVerifyBasics(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = response
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), getClient(), getUser());
        return tokenResponse;
    }

    default void assertAuthCodeIsRejected(String authorizationCode) {
        tokenEndpoint().request(getClient(), authorizationCode)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid code"));
    }
}
