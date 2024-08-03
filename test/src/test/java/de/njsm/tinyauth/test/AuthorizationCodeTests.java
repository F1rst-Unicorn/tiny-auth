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
import de.njsm.tinyauth.test.data.Tokens;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.runtime.Browser;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static de.njsm.tinyauth.test.oidc.Identifiers.AUTH_TIME;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public interface AuthorizationCodeTests extends AuthorizationCodeGadgets, ClientSetter {

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-codereuse")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-codereuse")
    default void authenticateAndTryToUseTheSameAuthorizationCodeTwice(Browser browser) throws Exception {
        String authorizationCode = authenticateReturningAuthCode(browser);
        assertAuthCodeIsRejected(authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-codereuse-30seconds")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-codereuse-30seconds")
    default void authenticateAndTryToUseTheSameAuthorizationCodeTwiceWithDelay(Browser browser) throws Exception {
        String authorizationCode = authenticateReturningAuthCode(browser);
        Thread.sleep(30000);
        assertAuthCodeIsRejected(authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-server-client-secret-post")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-server-client-secret-post")
    default void authenticateWithClientPasswordPostBody(Browser browser) throws Exception {
        String authCode = fetchAuthCode(browser, getScopes());
        verifyTokensFromAuthorizationCodeWithClientPost(getScopes(), authCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-login-hint")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-login-hint")
    default void authenticateWithLoginHint(Browser browser) throws Exception {
        String loginHint = getUser().getUsername();
        browser.startAuthenticationWithAdditionalParameters(getClient(), getState(), getScopes(), getNonce(), Map.of("login_hint", loginHint))
                .assertUserIsPrefilled(loginHint)
                .withPassword(getUser().getPassword())
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect(browser);
        verifyTokensFromAuthorizationCode(getScopes(), authorizationCode);
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-prompt-none-logged-in")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-prompt-none-logged-in")
    default void authenticateTwiceWithPasswordless(Browser browser) throws Exception {
        setClient(Clients.getClientForNoPromptTest());

        browser.startAuthentication(getClient(), getState(), getScopes(), getNonce())
                .withUser(getUser())
                .loginAndAssumeScopesAreGranted();
        String authorizationCode = assertOnRedirect(browser);
        OidcToken tokenFromFirstLogin = verifyTokensFromAuthorizationCode(getScopes(), authorizationCode).accessToken().get();

        browser.startAuthenticationWithoutInteraction(getClient(), getState(), getScopes(), getNonce(), Map.of("prompt", "none"));
        authorizationCode = assertOnRedirect(browser);
        OidcToken tokenFromSecondLogin = verifyTokensFromAuthorizationCode(getScopes(), authorizationCode).accessToken().get();

        long firstAuthTime = tokenFromFirstLogin.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = tokenFromSecondLogin.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));

        String firstSubject = tokenFromFirstLogin.getClaims().getSubject();
        String secondSubject = tokenFromSecondLogin.getClaims().getSubject();
        assertThat(firstSubject, is(equalTo(secondSubject)));
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-max-age-10000")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-max-age-10000")
    default void authenticateWithMaxAgeWithoutLogin(Browser browser) throws Exception {
        OidcToken firstToken = authenticateWithAdditionalParameters(browser, Map.of("max_age", "15000")).accessToken().get();

        browser.startAuthenticationWithConsent(getClient(), getState(), getScopes(), getNonce(), Map.of("max_age", "10000"))
                .confirm();
        String authorizationCode = assertOnRedirect(browser);
        OidcToken secondToken = verifyTokensFromAuthorizationCode(getScopes(), authorizationCode).accessToken().get();

        long firstAuthTime = firstToken.getClaims().getLongClaim(AUTH_TIME);
        long secondAuthTime = secondToken.getClaims().getLongClaim(AUTH_TIME);
        assertThat(firstAuthTime, is(equalTo(secondAuthTime)));
    }


    @Override
    default OidcToken selectToken(Tokens tokens) {
        return tokens.accessToken().orElseThrow();
    }
}
