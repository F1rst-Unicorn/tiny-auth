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
import de.njsm.tinyauth.test.oidc.redirect.RedirectFragmentExtractor;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.repository.Scopes;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class ImplicitAuthenticationTest extends TinyAuthBrowserTest implements Gadgets, RedirectFragmentExtractor {

    @BeforeEach
    void setUp() {
        client = Clients.getPublicClient();
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-login-hint")
    void authenticateWithLoginHint(Browser browser) throws Exception {
        String loginHint = user.getUsername();
        browser.startAuthenticationWithAdditionalParameters(client, getState(), scopes, getNonce(), Map.of("login_hint", loginHint))
                .assertUserIsPrefilled(loginHint)
                .withPassword(user.getPassword())
                .login()
                .confirm();

        extractTokenFromRedirect(browser);
    }

    @Test
    @Tag("oidcc-implicit-certification-test-plan.oidcc-max-age-10000")
    void authenticateWithMaxAgeWithoutLogin(Browser browser) throws Exception {
        OidcToken firstToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "15000"));

        browser.startAuthenticationWithConsent(client, getState(), scopes, getNonce(), Map.of("max_age", "10000"))
                .confirm();
        OidcToken secondToken = extractTokenFromRedirect(browser);

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));
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
    @Tag("oidcc-implicit-certification-test-plan.oidcc-prompt-none-logged-in")
    void authenticateTwiceWithPasswordless(Browser browser) throws Exception {
        client = Clients.getClientForNoPromptTest();

        browser.startAuthentication(client, getState(), scopes, getNonce())
                .withUser(user)
                .loginAndAssumeScopesAreGranted();
        OidcToken tokenFromFirstLogin = extractTokenFromRedirect(browser);

        browser.startAuthenticationWithoutInteraction(client, getState(), scopes, getNonce(), Map.of("prompt", "none"));
        OidcToken tokenFromSecondLogin = extractTokenFromRedirect(browser);

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));

        String firstSubject = tokenFromFirstLogin.getClaims().getSubject();
        String secondSubject = tokenFromSecondLogin.getClaims().getSubject();
        assertThat(firstSubject, is(equalTo(secondSubject)));
    }

    public OidcToken authenticateWithAdditionalParameters(Browser browser, Map<String, String> additionalParameters) throws Exception {
        browser.startAuthenticationWithAdditionalParameters(client, getState(), scopes, getNonce(), additionalParameters)
                .withUser(user)
                .login()
                .confirm();

        return extractTokenFromRedirect(browser);
    }

    public OidcToken authenticate(Browser browser) throws Exception {
        return authenticate(browser, getScopes());
    }

    public OidcToken authenticate(Browser browser, Set<String> scopes) throws Exception {
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
}
