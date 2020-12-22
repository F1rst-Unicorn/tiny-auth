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
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.repository.Scopes;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.*;

import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.fail;

public class IdTokenAuthenticationTest extends ImplicitAuthenticationTest {

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-server")
    void authenticateSuccessfully(Browser browser) throws Exception {
        authenticate(browser);
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-without-nonce-fails")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/68")
    void authenticateWithoutNonceFails(Browser browser) {
        browser.startAuthenticationWithoutNonceGivingError(client, getStateParameter(), scopes);

        HttpUrl oidcRedirect = getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());
        assertUrlParameter(oidcRedirect, ERROR, "invalid_request");
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-profile")
    void authenticateWithProfileScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "profile"));
        Scopes.getProfile().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-email")
    void authenticateWithEmailScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "email"));
        Scopes.getEmail().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-address")
    void authenticateWithAddressScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "address"));
        Scopes.getAddress().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-phone")
    void authenticateWithPhoneScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "phone"));
        Scopes.getPhone().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-all")
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-other-scope-order-succeeds")
    void authenticateWithScopesInDifferentOrder(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "email"));
        Scopes.getEmail().verifyClaimsFor(user, accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-display-page")
    void authenticateWithDisplayPage(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "page"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-display-popup")
    void authenticateWithDisplayPopup(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "popup"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-login")
    void authenticateTwiceWithForcedLogin(Browser browser) throws Exception {
        OidcToken tokenFromFirstLogin = authenticate(browser);
        OidcToken tokenFromSecondLogin = authenticateWithAdditionalParameters(browser, Map.of("prompt", "login"));

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-none-not-logged-in")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/68")
    void authenticateWithForcedPasswordless(Browser browser) {
        Set<String> scopes = Set.of("openid");
        browser.startAuthenticationWithoutInteraction(client, getStateParameter(), scopes, getNonceParameter(), Map.of("prompt", "none"));

        HttpUrl oidcRedirect = getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getStateParameter());
        assertUrlParameter(oidcRedirect, ERROR, "login_required");
        assertUrlParameter(oidcRedirect, ERROR_DESCRIPTION, "No username found");
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-none-logged-in")
    void authenticateTwiceWithPasswordless(Browser browser) throws Exception {
        client = Clients.getClientForNoPromptTest();

        browser.startAuthentication(client, getStateParameter(), scopes, getNonceParameter())
                .withUser(user)
                .loginAndAssumeScopesAreGranted();
        OidcToken tokenFromFirstLogin = extractTokenFromRedirect(browser);

        browser.startAuthenticationWithoutInteraction(client, getStateParameter(), scopes, getNonceParameter(), Map.of("prompt", "none"));
        OidcToken tokenFromSecondLogin = extractTokenFromRedirect(browser);

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));

        String firstSubject = tokenFromFirstLogin.getClaims().getSubject();
        String secondSubject = tokenFromSecondLogin.getClaims().getSubject();
        assertThat(firstSubject, is(equalTo(secondSubject)));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-max-age-1")
    void authenticateWithMaxAge(Browser browser) throws Exception {
        OidcToken firstToken = authenticate(browser);

        Thread.sleep(2000);
        OidcToken secondToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "1"));

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-max-age-10000")
    void authenticateWithMaxAgeWithoutLogin(Browser browser) throws Exception {
        OidcToken firstToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "15000"));

        browser.startAuthenticationWithConsent(client, getStateParameter(), scopes, getNonceParameter(), Map.of("max_age", "10000"))
                .confirm();
        OidcToken secondToken = extractTokenFromRedirect(browser);

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-with-unknown-parameter-succeeds")
    void authenticateWithUnknownExtraParameter(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("extra", "foobar"));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-id-token-hint")
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-login-hint")
    void authenticateWithLoginHint(Browser browser) throws Exception {
        String loginHint = user.getUsername();
        browser.startAuthenticationWithAdditionalParameters(client, getStateParameter(), scopes, getNonceParameter(), Map.of("login_hint", loginHint))
                .assertUserIsPrefilled(loginHint)
                .withPassword(user.getPassword())
                .login()
                .confirm();

        extractTokenFromRedirect(browser);
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ui-locales")
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-claims-locales")
    void authenticateWithClaimsLocales(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("claims_locale", "se"));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-with-acr-values-succeeds")
    void authenticateWithAcrValues(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("acr_values", "1 2"));
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-registered-redirect-uri")
    void authenticateWithInvalidRedirectUri(Browser browser) {
        String redirectUri = "http://invalid.example/invalid";
        browser.startAuthenticationWithInvalidRedirectUri(client, getStateParameter(), scopes, getNonceParameter(), redirectUri);
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-userinfo-get")
    void authenticateAndQueryUserinfoEndpoint(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser);

        JsonPath userinfo = userinfoEndpoint().getUserinfo(accessToken.getRawToken());

        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Override
    Set<ResponseType> getResponseTypes() {
        return Set.of(ResponseType.ID_TOKEN);
    }
}
