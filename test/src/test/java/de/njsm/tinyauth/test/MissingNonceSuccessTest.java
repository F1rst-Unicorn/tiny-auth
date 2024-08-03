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

import de.njsm.tinyauth.test.oidc.TokenAsserter;
import de.njsm.tinyauth.test.oidc.TokenAsserterWithoutNonce;
import de.njsm.tinyauth.test.runtime.Browser;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.junit.jupiter.api.Assertions.assertEquals;

public interface MissingNonceSuccessTest extends AuthorizationCodeGadgets {

    @Override
    default TokenAsserter tokenAsserter() {
        return new TokenAsserterWithoutNonce(endpoint());
    }

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-without-nonce-succeeds-for-code-flow")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-request-without-nonce-succeeds-for-code-flow")
    default void authenticateWithoutNonce(Browser browser) throws Exception {
        browser.startAuthenticationWithoutNonce(getClient(), getState(), getScopes())
                .withUser(getUser())
                .login()
                .confirm();

        String authorizationCode = assertOnRedirect(browser);

        JsonPath tokenResponse = tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(getClient(), authorizationCode)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(getScopes(), Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyToken(tokenResponse.getString(ACCESS_TOKEN), getClient(), getUser());
        tokenAsserter().verifyToken(tokenResponse.getString(ID_TOKEN), getClient(), getUser());
        tokenAsserter().verifyRefreshToken(tokenResponse.getString(REFRESH_TOKEN), getClient(), getUser(), getScopes());
    }
}
