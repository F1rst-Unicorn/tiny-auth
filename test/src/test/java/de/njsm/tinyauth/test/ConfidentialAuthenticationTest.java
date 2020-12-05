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
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.util.List;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("response_type.code")
public class ConfidentialAuthenticationTest extends TinyAuthBrowserTest {

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-server")
    void authenticateSuccessfully(Browser browser) throws Exception {
        authenticate(browser);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-response-type-missing")
    void missingResponseTypeIsReported(Browser browser) {
        Client client = Clients.getConfidentialClient();
        Set<String> scopes = Set.of("openid");

        browser.startAuthenticationWithMissingResponseType(client, getStateParameter(), scopes, getNonceParameter());

        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertTrue(oidcRedirect.getQueryStringParameters().containsEntry(STATE, getStateParameter()), "state <" + getStateParameter() + "> not found");
        assertTrue(oidcRedirect.getQueryStringParameters().containsEntry(ERROR, "invalid_request"), "error not set or wrong value");
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-get")
    void authenticateAndQueryUserinfoEndpoint(Browser browser) throws Exception {
        String accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().getUserinfo(accessToken);

        tokenAsserter().verifyUserinfo(userinfo, accessToken);
    }

    /**
     * Omits doing a GET request to userinfo as well. This is different from the
     * official conformance test.
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-post-header")
    void authenticateAndQueryUserinfoEndpointWithPost(Browser browser) throws Exception {
        String accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken);

        tokenAsserter().verifyUserinfo(userinfo, accessToken);
    }

    /**
     * Omits doing a GET request to userinfo as well. This is different from the
     * official conformance test.
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-post-body")
    void authenticateAndQueryUserinfoEndpointWithPostBody(Browser browser) throws Exception {
        String accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().postUserinfoWithTokenInBody(accessToken);

        tokenAsserter().verifyUserinfo(userinfo, accessToken);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-without-nonce-succeeds-for-code-flow")
    void authenticateWithoutNonce(Browser browser) throws Exception {
        User user = Users.getUser();
        Client client = Clients.getConfidentialClient();
        Set<String> scopes = Set.of("openid");

        browser.startAuthenticationWithoutNonce(client, getStateParameter(), scopes)
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();

        JsonPath tokenResponse = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authorizationCode)
                .body(SCOPE, equalTo(String.join(" ", scopes)))
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user);
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user);
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, scopes);
    }

    private String authenticate(Browser browser) throws Exception {
        User user = Users.getUser();
        Client client = Clients.getConfidentialClient();
        Set<String> scopes = Set.of("openid");

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();

        JsonPath tokenResponse = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authorizationCode)
                .body(SCOPE, equalTo(String.join(" ", scopes)))
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);

        return tokenResponse.getString(ACCESS_TOKEN);
    }

    @NotNull
    private String assertOnRedirect() {
        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertTrue(oidcRedirect.getQueryStringParameters().containsEntry(STATE, getStateParameter()), "state <" + getStateParameter() + "> not found");

        List<String> errors = oidcRedirect.getQueryStringParameters().getValues(ERROR);
        assertTrue(errors.isEmpty(), "server returned error: " + String.join(" ", errors));

        String authorizationCode = oidcRedirect.getFirstQueryStringParameter(ResponseType.CODE.get());
        assertThat(authorizationCode.length(), is(greaterThanOrEqualTo(16)));
        return authorizationCode;
    }
}
