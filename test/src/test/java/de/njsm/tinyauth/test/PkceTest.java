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

import com.google.common.hash.Hashing;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.Tokens;
import de.njsm.tinyauth.test.oidc.Identifiers;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.runtime.Browser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.Matchers.equalTo;

/**
 * <a href="https://www.rfc-editor.org/rfc/rfc7636">RFC</a>
 */
public class PkceTest extends TinyAuthBrowserTest implements AuthorizationCodeGadgets {

    @Test
    void tokenIsNotIssuedWithoutCodeVerifier(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, Map.of(
                        CODE_CHALLENGE, buildCodeChallenge(),
                        CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD_S256));

        tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(getClient(), authorizationCode, Map.of())
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid code"));
    }

    @Test
    void tokenIsNotIssuedWithWrongCodeVerifier(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, Map.of(
                        CODE_CHALLENGE, buildCodeChallenge(),
                        CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD_S256));

        tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(getClient(), authorizationCode, Map.of(
                        CODE_VERIFIER, "wrong-codewrong-codewrong-codewrong-codewrong-code"
                ))
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("Invalid code"));
    }

    @Test
    void tokenIsIssuedForValidRequest(Browser browser) throws Exception {
        String authorizationCode = fetchAuthCode(browser, Map.of(
                        CODE_CHALLENGE, buildCodeChallenge(),
                        CODE_CHALLENGE_METHOD, CODE_CHALLENGE_METHOD_S256));

        verifyTokensFromResponse(scopes, tokenEndpoint().requestWithAuthorizationCodeAndBasicAuth(
                getClient(),
                authorizationCode,
                Map.of(CODE_VERIFIER, getCodeVerifier())));
    }

    private String buildCodeChallenge() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                Hashing.sha256()
                        .hashString(getCodeVerifier(), StandardCharsets.UTF_8)
                        .asBytes()
        );
    }

    @BeforeEach
    void setUp() {
        client = Clients.getConfidentialClient();
    }

    @Override
    public Set<Identifiers.ResponseType> getResponseTypes() {
        return Set.of(Identifiers.ResponseType.CODE);
    }

    @Override
    public OidcToken selectToken(Tokens tokens) {
        throw new UnsupportedOperationException("unused anyway");
    }
}
