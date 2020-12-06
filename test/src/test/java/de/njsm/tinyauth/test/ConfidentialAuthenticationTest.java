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
import de.njsm.tinyauth.test.repository.Scopes;
import de.njsm.tinyauth.test.repository.Users;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("response_type.code")
public class ConfidentialAuthenticationTest extends TinyAuthBrowserTest {

    private final User user = Users.getUser();

    private final Client client = Clients.getConfidentialClient();

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
        OidcToken accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().getUserinfo(accessToken.getRawToken());

        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    /**
     * Omits doing a GET request to userinfo as well. This is different from the
     * official conformance test.
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-post-header")
    void authenticateAndQueryUserinfoEndpointWithPost(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());

        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    /**
     * Omits doing a GET request to userinfo as well. This is different from the
     * official conformance test.
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-post-body")
    void authenticateAndQueryUserinfoEndpointWithPostBody(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().postUserinfoWithTokenInBody(accessToken.getRawToken());

        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-without-nonce-succeeds-for-code-flow")
    void authenticateWithoutNonce(Browser browser) throws Exception {
        Set<String> scopes = Set.of("openid");

        browser.startAuthenticationWithoutNonce(client, getStateParameter(), scopes)
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();

        JsonPath tokenResponse = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authorizationCode)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyAccessTokenWithoutNonce(tokenResponse.getString(ACCESS_TOKEN), client, user);
        tokenAsserter().verifyAccessTokenWithoutNonce(tokenResponse.getString(ID_TOKEN), client, user);
        tokenAsserter().verifyRefreshTokenWithoutNonce(tokenResponse.getString(REFRESH_TOKEN), client, user, scopes);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-profile")
    void authenticateWithProfileScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "profile"));
        Scopes.getProfile().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-email")
    void authenticateWithEmailScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "email"));
        Scopes.getEmail().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-address")
    void authenticateWithAddressScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "address"));
        Scopes.getAddress().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-phone")
    void authenticateWithPhoneScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "phone"));
        Scopes.getPhone().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-all")
    void authenticateWithAllScopes(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "profile", "email", "address", "phone"));
        Scopes.getProfile().verifyClaimsFor(user, accessToken.getClaims());
        Scopes.getEmail().verifyClaimsFor(user, accessToken.getClaims());
        Scopes.getAddress().verifyClaimsFor(user, accessToken.getClaims());
        Scopes.getPhone().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-display-page")
    void authenticateWithDisplayPage(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "page"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-display-popup")
    void authenticateWithDisplayPopup(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "popup"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-login")
    void authenticateTwiceWithForcedLogin(Browser browser) throws Exception {
        OidcToken tokenFromFirstLogin = authenticate(browser);
        OidcToken tokenFromSecondLogin = authenticateWithAdditionalParameters(browser, Map.of("prompt", "login"));

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    private OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        Set<String> scopes = Set.of("openid");
        browser.startAuthenticationWithAdditionalParameters(client, getStateParameter(), scopes, getNonceParameter(), additionalParameters)
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    private OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    private OidcToken verifyTokensFromAuthorizationCode(Set<String> scopes, String authorizationCode) throws Exception {
        JsonPath tokenResponse = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authorizationCode)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        OidcToken oidcToken = tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user, getNonceParameter());
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
        return oidcToken;
    }

    private OidcToken authenticate(Browser browser) throws Exception {
        return authenticate(browser, Set.of("openid"));
    }

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
