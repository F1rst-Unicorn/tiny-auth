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

package de.njsm.tinyauth.test.oidc;

import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Endpoint;

import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.NONCE;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TokenAsserterWithNonce implements TokenAsserter {

    private final Endpoint endpoint;

    private final String nonce;

    public TokenAsserterWithNonce(Endpoint endpoint, String nonce) {
        this.endpoint = endpoint;
        this.nonce = nonce;
    }

    @Override
    public OidcToken verifyRefreshToken(String token, Client client, User user, Set<String> scopes) throws Exception {
        OidcToken result = TokenAsserter.super.verifyRefreshToken(token, client, user, scopes);
        assertEquals(nonce, result.getClaims().getClaims().get(NONCE));
        return result;
    }

    @Override
    public void verifyAccessTokenClaims(Map<String, Object> claims, Client client, User user) {
        TokenAsserter.super.verifyAccessTokenClaims(claims, client, user);
        assertEquals(nonce, claims.get(NONCE));
    }

    @Override
    public Endpoint endpoint() {
        return endpoint;
    }
}
