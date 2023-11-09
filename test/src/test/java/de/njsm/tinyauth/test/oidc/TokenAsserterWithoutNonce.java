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

import com.nimbusds.jwt.JWTClaimsSet;
import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Endpoint;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.ACCESS_TOKEN;

public class TokenAsserterWithoutNonce implements TokenAsserter {

    private final Endpoint endpoint;

    public TokenAsserterWithoutNonce(Endpoint endpoint) {
        this.endpoint = endpoint;
    }

    @Override
    public OidcToken verifyAccessToken(String token, Client client, User user) throws Exception {
        JWTClaimsSet claims = verifyToken(token);
        verifyAccessTokenClaims(claims.getClaims(), client, user);
        return new OidcToken(token, claims);
    }

    @Override
    public OidcToken verifyRefreshToken(String token, Client client, User user, Set<String> scopes) throws Exception {
        JWTClaimsSet claims = verifyRefreshTokenSpecificClaims(token, scopes);
        verifyAccessTokenClaims(claims.getJSONObjectClaim(ACCESS_TOKEN), client, user);
        return new OidcToken(token, claims);
    }

    @Override
    public Endpoint endpoint() {
        return endpoint;
    }
}
