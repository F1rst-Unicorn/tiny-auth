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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Endpoints;
import io.restassured.path.json.JsonPath;

import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenAsserter {

    public OidcToken verifyAccessTokenWithoutNonce(String token, Client client, User user) throws Exception {
        JWTClaimsSet claims = verifyToken(token);
        verifyAccessTokenClaimsWithoutNonce(claims.getClaims(), client, user);
        return new OidcToken(token, claims);
    }

    public OidcToken verifyAccessToken(String token, Client client, User user, String nonce) throws Exception {
        JWTClaimsSet claims = verifyToken(token);
        verifyAccessTokenClaims(claims.getClaims(), client, user, nonce);
        return new OidcToken(token, claims);
    }

    public OidcToken verifyRefreshToken(String token, Client client, User user, String nonce, Set<String> scopes) throws Exception {
        JWTClaimsSet claims = verifyRefreshTokenSpecificClaims(token, scopes);
        verifyAccessTokenClaims(claims.getJSONObjectClaim(ACCESS_TOKEN), client, user, nonce);
        return new OidcToken(token, claims);
    }

    public OidcToken verifyRefreshTokenWithoutNonce(String token, Client client, User user, Set<String> scopes) throws Exception {
        JWTClaimsSet claims = verifyRefreshTokenSpecificClaims(token, scopes);
        verifyAccessTokenClaimsWithoutNonce(claims.getJSONObjectClaim(ACCESS_TOKEN), client, user);
        return new OidcToken(token, claims);
    }

    public void verifyUserinfo(JsonPath userinfo, JWTClaimsSet accessTokenClaims) {
        Map<String, Object> convertedClaims = new HashMap<>(accessTokenClaims.getClaims());
        convertedClaims.put(EXPIRATION_TIME, ((Date) convertedClaims.get(EXPIRATION_TIME)).getTime() / 1000);
        convertedClaims.put(ISSUANCE_TIME, ((Date) convertedClaims.get(ISSUANCE_TIME)).getTime() / 1000);

        Map<String, Object> convertedUserinfo = new HashMap<>(userinfo.getMap(""));
        Object audience = convertedUserinfo.get(AUDIENCE);
        if (audience instanceof String)
            convertedUserinfo.put(AUDIENCE, singletonList(audience));
        else
            convertedUserinfo.put(AUDIENCE, audience);
        convertedUserinfo = convertedUserinfo.entrySet().stream()
                .peek(e -> {
                    if (e.getValue() instanceof Integer) {
                        e.setValue(Long.valueOf((Integer) e.getValue()));
                    }
                }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        assertEquals(convertedClaims, convertedUserinfo);
    }

    private JWTClaimsSet verifyRefreshTokenSpecificClaims(String token, Set<String> scopes) throws Exception {
        JWTClaimsSet claims = verifyToken(token);

        assertEquals(Endpoints.getIssuer(), claims.getStringClaim(ISSUER));
        assertEquals(scopes, new HashSet<>(claims.getStringListClaim(SCOPES)));
        assertTrue(claims.getExpirationTime().after(new Date()), "token has already expired");

        return claims;
    }

    private void verifyAccessTokenClaims(Map<String, Object> claims, Client client, User user, String nonce) {
        verifyAccessTokenClaimsWithoutNonce(claims, client, user);
        assertEquals(nonce, claims.get(NONCE));
    }

    private void verifyAccessTokenClaimsWithoutNonce(Map<String, Object> claims, Client client, User user) {
        Date now = new Date();

        assertEquals(Endpoints.getIssuer(), claims.get(ISSUER));
        assertEquals(client.getClientId(), claims.get(AUTHORIZED_PARTY));
        assertEquals(user.getUsername(), claims.get(SUBJECT));

        Object audience = claims.get(AUDIENCE);
        if (audience instanceof String)
            assertEquals(client.getClientId(), audience);
        else
            assertEquals(singletonList(client.getClientId()), audience);

        Date expirationTime = castToDate(claims.get(EXPIRATION_TIME));
        Date issuanceTime = castToDate(claims.get(ISSUANCE_TIME));
        Date authTime = castToDate(claims.get(AUTH_TIME));

        assertTrue(now.compareTo(expirationTime) < 1, "token has already expired");
        assertTrue(issuanceTime.compareTo(now) < 1, "token was issued in the future");
        assertTrue(authTime.compareTo(issuanceTime) < 1, "token was issued (" + issuanceTime + ") before authentication (" + authTime + ")");
    }

    private Date castToDate(Object rawDate) {
        if (rawDate instanceof Date)
            return (Date) rawDate;
        else
            return new Date((Long) rawDate * 1000);
    }

    private static JWTClaimsSet verifyToken(String token) throws Exception {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(Endpoints.getJwksUrl()));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.ES384;
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }
}
