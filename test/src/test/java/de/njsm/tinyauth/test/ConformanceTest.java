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
import de.njsm.tinyauth.test.oidc.redirect.RedirectQueryExtractor;
import de.njsm.tinyauth.test.repository.Scopes;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.fail;

public interface ConformanceTest extends TinyAuthTest, Gadgets {

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-server")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-server")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-server")
    default void authenticateSuccessfully(Browser browser) throws Exception {
        authenticate(browser);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-response-type-missing")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-response-type-missing")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-response-type-missing")
    default void missingResponseTypeIsReported(Browser browser) {
        browser.startAuthenticationWithMissingResponseType(getClient(), getState(), getScopes(), getNonce());

        HttpUrl oidcRedirect = new RedirectQueryExtractor(){}.getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getState());
        assertUrlParameter(oidcRedirect, ERROR, "invalid_request");
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-profile")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-profile")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-scope-profile")
    default void authenticateWithProfileScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "profile"));
        Scopes.getProfile().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-email")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-email")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-scope-email")
    default void authenticateWithEmailScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "email"));
        Scopes.getEmail().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-address")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-address")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-scope-address")
    default void authenticateWithAddressScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "address"));
        Scopes.getAddress().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-phone")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-phone")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-scope-phone")
    default void authenticateWithPhoneScope(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "phone"));
        Scopes.getPhone().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-scope-all")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-scope-all")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-scope-all")
    default void authenticateWithAllScopes(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("openid", "profile", "email", "address", "phone"));
        Scopes.getProfile().verifyClaimsFor(getUser(), accessToken.getClaims());
        Scopes.getEmail().verifyClaimsFor(getUser(), accessToken.getClaims());
        Scopes.getAddress().verifyClaimsFor(getUser(), accessToken.getClaims());
        Scopes.getPhone().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-other-scope-order-succeeds")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-other-scope-order-succeeds")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-other-scope-order-succeeds")
    default void authenticateWithDifferentScopeOrder(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser, Set.of("email", "openid"));
        Scopes.getEmail().verifyClaimsFor(getUser(), accessToken.getClaims());
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-display-page")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-display-page")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-display-page")
    default void authenticateWithDisplayPage(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "page"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-display-popup")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-display-popup")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-display-popup")
    default void authenticateWithDisplayPopup(Browser browser) throws Exception {
        OidcToken accessToken = authenticateWithAdditionalParameters(browser, Map.of("display", "popup"));
        JsonPath userinfo = userinfoEndpoint().postUserinfo(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-login")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-login")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-prompt-login")
    default void authenticateTwiceWithForcedLogin(Browser browser) throws Exception {
        OidcToken tokenFromFirstLogin = authenticate(browser);
        OidcToken tokenFromSecondLogin = authenticateWithAdditionalParameters(browser, Map.of("prompt", "login"));

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-max-age-1")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-max-age-1")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-max-age-1")
    default void authenticateWithMaxAge(Browser browser) throws Exception {
        OidcToken firstToken = authenticate(browser);

        Thread.sleep(2000);
        OidcToken secondToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "1"));

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(lessThan(secondAuthTime)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-with-unknown-parameter-succeeds")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-with-unknown-parameter-succeeds")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-request-with-unknown-parameter-succeeds")
    default void authenticateWithUnknownExtraParameter(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("extra", "foobar"));
    }

    /**
     * This will likely never get more sophisticated semantics than to be ignored
     */
    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-claims-locales")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-claims-locales")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-claims-locales")
    default void authenticateWithClaimsLocales(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("claims_locale", "se"));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-with-acr-values-succeeds")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-with-acr-values-succeeds")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-request-with-acr-values-succeeds")
    default void authenticateWithAcrValues(Browser browser) throws Exception {
        authenticateWithAdditionalParameters(browser, Map.of("acr_values", "1 2"));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-userinfo-get")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-userinfo-get")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-userinfo-get")
    default void authenticateAndQueryUserinfoEndpoint(Browser browser) throws Exception {
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-userinfo-post-header")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-userinfo-post-header")
    default void authenticateAndPostUserinfo(Browser browser) throws Exception {
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-userinfo-post-body")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-userinfo-post-body")
    default void authenticateAndPostUserinfoInBody(Browser browser) throws Exception {
        OidcToken accessToken = authenticate(browser);
        JsonPath userinfo = userinfoEndpoint().postUserinfoWithTokenInBody(accessToken.getRawToken());
        tokenAsserter().verifyUserinfo(userinfo, accessToken.getClaims());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-registered-redirect-uri")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-registered-redirect-uri")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-registered-redirect-uri")
    default void authenticateWithInvalidRedirectUri(Browser browser) {
        String redirectUri = "http://invalid.example/invalid";
        browser.startAuthenticationWithInvalidRedirectUri(getClient(), getState(), getScopes(), getNonce(), redirectUri);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-none-not-logged-in")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-none-not-logged-in")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-prompt-none-not-logged-in")
    default void authenticateWithForcedPasswordless(Browser browser) {
        browser.startAuthenticationWithoutInteraction(getClient(), getState(), getScopes(), getNonce(), Map.of("prompt", "none"));

        HttpUrl oidcRedirect = getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getState());
        assertUrlParameter(oidcRedirect, ERROR, "login_required");
        assertUrlParameter(oidcRedirect, ERROR_DESCRIPTION, "No username found");
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-id-token-hint")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-id-token-hint")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-id-token-hint")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/53")
    default void authenticateWithIdTokenHint() {
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
    @Tag("oidcc-basic-certification-test-plan.oidcc-ui-locales")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ui-locales")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ui-locales")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/22")
    default void authenticateWithUiLocale() {
        fail("This test includes the ui_locales parameter in the request to " +
                "the authorization endpoint, with the value set to that " +
                "provided in the configuration (or 'se' if no value " +
                "probably). Use of this parameter in the request must not " +
                "cause an error at the OP. Please remove any cookies you " +
                "may have received from the OpenID Provider before " +
                "proceeding. You need to do this so you can check that the " +
                "login page is displayed using one of the requested locales.");
    }
}
