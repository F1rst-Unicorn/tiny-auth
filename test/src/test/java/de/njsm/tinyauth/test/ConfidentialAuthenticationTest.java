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
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockserver.model.HttpRequest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@Tag("response_type.code")
public class ConfidentialAuthenticationTest extends TinyAuthBrowserTest {

    private final User user = Users.getUser();

    private Client client = Clients.getConfidentialClient();

    private final Set<String> scopes = Set.of("openid");

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-server")
    void authenticateSuccessfully(Browser browser) throws Exception {
        authenticate(browser);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-response-type-missing")
    void missingResponseTypeIsReported(Browser browser) {
        browser.startAuthenticationWithMissingResponseType(client, getStateParameter(), scopes, getNonceParameter());

        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());
        assertUrlParameter(oidcRedirect, ERROR, "invalid_request");
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

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-none-not-logged-in")
    void authenticateWithForcedPasswordless(Browser browser) {
        Set<String> scopes = Set.of("openid");
        browser.startAuthenticationWithoutInteraction(client, getStateParameter(), scopes, getNonceParameter(), Map.of("prompt", "none"));

        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());
        assertUrlParameter(oidcRedirect, ERROR, "login_required");
        assertUrlParameter(oidcRedirect, ERROR_DESCRIPTION, "No username found");
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-none-logged-in")
    void authenticateTwiceWithPasswordless(Browser browser) throws Exception {
        client = Clients.getClientForNoPromptTest();

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .loginAndAssumeScopesAreGranted();
        String authorizationCode = assertOnRedirect();
        OidcToken tokenFromFirstLogin = verifyTokensFromAuthorizationCode(scopes, authorizationCode);

        browser.startAuthenticationWithoutInteraction(client, getStateParameter(), scopes, getNonceParameter(), Map.of("prompt", "none"));
        authorizationCode = assertOnRedirect();
        OidcToken tokenFromSecondLogin = verifyTokensFromAuthorizationCode(scopes, authorizationCode);

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));

        String firstSubject = tokenFromFirstLogin.getClaims().getSubject();
        String secondSubject = tokenFromSecondLogin.getClaims().getSubject();
        assertThat(firstSubject, is(equalTo(secondSubject)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-max-age-1")
    void authenticateWithMaxAge(Browser browser) throws Exception {
        OidcToken firstToken = authenticate(browser);

        Thread.sleep(1000);
        OidcToken secondToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "1"));

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-max-age-10000")
    void authenticateWithMaxAgeWithoutLogin(Browser browser) throws Exception {
        OidcToken firstToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "15000"));

        browser.startAuthenticationWithConsent(client, getStateParameter(), scopes, getNonceParameter(), Map.of("max_age", "10000"))
                .confirm();
        String authorizationCode = assertOnRedirect();
        OidcToken secondToken = verifyTokensFromAuthorizationCode(scopes, authorizationCode);

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-with-unknown-parameter-succeeds")
    void authenticateWithUnknownExtraParameter(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("extra", "foobar"));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-id-token-hint")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/53")
    void authenticateWithIdTokenHint() {
        fail("This test calls the authorization endpoint test twice. " +
                "The second time it will include prompt=none with the " +
                "id_token_hint set to the id token from the first " +
                "authorization, and the authorization server must return " +
                "successfully immediately without interacting with the user. " +
                "The test verifies that auth_time (if present) and sub are " +
                "consistent between the id_tokens from the first and second " +
                "authorizations.");
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-login-hint")
    void authenticateWithLoginHint(Browser browser) throws Exception {
        String loginHint = user.getUsername();
        browser.startAuthenticationWithAdditionalParameters(client, getStateParameter(), scopes, getNonceParameter(), Map.of("login_hint", loginHint))
                .assertUserIsPrefilled(loginHint)
                .withPassword(user.getPassword())
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();
        verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ui-locales")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/22")
    void authenticateWithUiLocale() {
        fail("This test includes the ui_locales parameter in the request to " +
                "the authorization endpoint, with the value set to that " +
                "provided in the configuration (or 'se' if no value " +
                "probably). Use of this parameter in the request must not " +
                "cause an error at the OP. Please remove any cookies you " +
                "may have received from the OpenID Provider before " +
                "proceeding. You need to do this so you can check that the " +
                "login page is displayed using one of the requested locales.");
    }

    /**
     * This will likely never get more sophisticated semantics than to be ignored
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-claims-locales")
    void authenticateWithClaimsLocales(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("claims_locale", "se"));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-with-acr-values-succeeds")
    void authenticateWithAcrValues(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("acr_values", "1 2"));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-codereuse")
    void authenticateAndTryToUseTheSameAuthorizationCodeTwice(Browser browser) throws Exception {
        String authorizationCode = authenticateReturningAuthCode(browser);
        assertAuthCodeIsRejected(authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-codereuse-30seconds")
    void authenticateAndTryToUseTheSameAuthorizationCodeTwiceWithDelay(Browser browser) throws Exception {
        String authorizationCode = authenticateReturningAuthCode(browser);
        Thread.sleep(30000);
        assertAuthCodeIsRejected(authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-registered-redirect-uri")
    void authenticateWithInvalidRedirectUri(Browser browser) {
        String redirectUri = "http://invalid.example/invalid";
        browser.startAuthenticationWithInvalidRedirectUri(client, getStateParameter(), scopes, getNonceParameter(), redirectUri);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-server-client-secret-post")
    void authenticateWithClientPasswordPostBody(Browser browser) throws Exception {
        String authCode = fetchAuthCode(browser, scopes);
        verifyTokensFromAuthorizationCodeWithClientPost(scopes, authCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-refresh-token")
    void authenticateAndTryRefreshToken(Browser browser) throws Exception {
        Client client1 = client;
        Client client2 = Clients.getClientForTokenSwitchAttack();

        String authCode = fetchAuthCode(browser, scopes);
        OidcToken firstRefreshToken = verifyTokensFromAuthorizationCodeReturningRefreshToken(scopes, authCode);
        verifyTokensFromAuthorizationCode(scopes, tokenEndpoint().requestWithRefreshToken(client, firstRefreshToken, scopes));

        client = client2;
        browser.resetCookies();

        authCode = fetchAuthCode(browser, scopes);
        OidcToken secondRefreshToken = verifyTokensFromAuthorizationCodeReturningRefreshToken(scopes, authCode);
        verifyTokensFromAuthorizationCode(scopes, tokenEndpoint().requestWithRefreshToken(client, secondRefreshToken, scopes));

        client = client1;
        tokenEndpoint().request(client, secondRefreshToken, scopes)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid refresh token"));
    }

    private OidcToken authenticate(Browser browser) throws Exception {
        return authenticate(browser, scopes);
    }

    private String authenticateReturningAuthCode(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, scopes);
        verifyTokensFromAuthorizationCode(scopes, authorizationCode);
        return authorizationCode;
    }

    private OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(client, getStateParameter(), scopes, getNonceParameter(), additionalParameters)
                .withUser(user)
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect();
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    private OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
        String authorizationCode = fetchAuthCode(browser, scopes);
        return verifyTokensFromAuthorizationCode(scopes, authorizationCode);
    }

    private String fetchAuthCode(Browser browser, Set<String> scopes) {
        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .login()
                .confirm();

        return assertOnRedirect();
    }

    private OidcToken verifyTokensFromAuthorizationCode(Set<String> scopes, String authCode) throws Exception {
        return verifyTokensFromAuthorizationCode(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authCode));
    }

    private void verifyTokensFromAuthorizationCodeWithClientPost(Set<String> scopes, String authCode) throws Exception {
        verifyTokensFromAuthorizationCode(scopes, tokenEndpoint().requestWithAuthorizationCodeAndClientSecretPost(client, authCode));
    }

    private OidcToken verifyTokensFromAuthorizationCodeReturningRefreshToken(Set<String> scopes, String authCode) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(client, authCode));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
        return tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
    }

    private OidcToken verifyTokensFromAuthorizationCode(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = fetchTokensAndVerifyBasics(scopes, response);
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), client, user, getNonceParameter(), scopes);
        return tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user, getNonceParameter());
    }

    private JsonPath fetchTokensAndVerifyBasics(Set<String> scopes, ValidatableResponse response) throws Exception {
        JsonPath tokenResponse = response
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        assertEquals(tokenResponse.getString(ACCESS_TOKEN), tokenResponse.getString(ID_TOKEN), "access token different from id token");
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user, getNonceParameter());
        return tokenResponse;
    }

    private void assertAuthCodeIsRejected(String authorizationCode) {
        tokenEndpoint().request(client, authorizationCode)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid code"));
    }

    private String assertOnRedirect() {
        HttpRequest oidcRedirect = getLastOidcRedirect();
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());

        List<String> errors = oidcRedirect.getQueryStringParameters().getValues(ERROR);
        assertTrue(errors.isEmpty(), "server returned error: " + String.join(" ", errors));

        String authorizationCode = oidcRedirect.getFirstQueryStringParameter(ResponseType.CODE.get());
        assertThat(authorizationCode.length(), is(greaterThanOrEqualTo(16)));
        return authorizationCode;
    }

    private void assertUrlParameter(HttpRequest oidcRedirect, String key, String value) {
        assertTrue(oidcRedirect.getQueryStringParameters().containsEntry(key, value),
                key + " was '" + oidcRedirect.getFirstQueryStringParameter(key) + "'");
    }
}
