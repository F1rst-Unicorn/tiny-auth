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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Clients;
import de.njsm.tinyauth.test.repository.Endpoint;
import de.njsm.tinyauth.test.repository.Users;
import io.restassured.path.json.JsonPath;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ApiTests implements TinyAuthTest, ApiGadgets {

    private Client client = Clients.getConfidentialClient();

    private final User user = Users.getUser();

    private Set<String> scopes = Set.of("openid");

    private Endpoint endpoint;

    @BeforeEach
    void setUp(Endpoint endpoint) {
        this.endpoint = endpoint;
    }

    @Test
    void testClientCredentialsGrant() throws Exception {
        authenticate(client, tokenEndpoint().requestWithClientCredentials(client, scopes));
    }

    @Test
    void clientCredentialsWithDisallowedScopeIsFiltered() throws Exception {
        scopes = Set.of("openid", "email");
        client = Clients.getRestrictedScopeClient();

        JsonPath tokenResponse = tokenEndpoint().requestWithClientCredentials(client, scopes)
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(Set.of("openid"), Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, client);
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, client);
    }

    @Test
    void testPasswordGrant() throws Exception {
        JsonPath tokenResponse = tokenEndpoint().requestWithPassword(client, user, scopes)
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user);
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user);
    }

    @Test
    void passwordGrantsDisallowedScopeIsFiltered() throws Exception {
        scopes = Set.of("openid", "email");
        client = Clients.getRestrictedScopeClient();

        JsonPath tokenResponse = tokenEndpoint().requestWithPassword(client, user, scopes)
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(Set.of("openid"), Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, user);
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, user);
    }

    @Test
    void passwordGrantIsRateLimited() {
        User user = Users.getRateLimitTestUser();
        String wrongPassword = "wrong-password";
        String errorDescription = "username or password wrong";
        int maxAllowed = 3;

        for (int i = 0; i < maxAllowed; i++) {
            tokenEndpoint().requestWithPassword(client, user, wrongPassword, scopes)
                    .statusCode(400)
                    .body(ERROR, equalTo(INVALID_GRANT))
                    .body(ERROR_DESCRIPTION, equalTo(errorDescription));
        }

        tokenEndpoint().requestWithPassword(client, user, scopes)
                .statusCode(400)
                .body(ERROR, equalTo(INVALID_GRANT))
                .body(ERROR_DESCRIPTION, equalTo("rate limited"));
    }

    @Test
    void clientCredentialsWorkWithSharedSecret() throws Exception {
        Client client = Clients.getAdvancedAuthClient();
        String token = buildTokenFromSharedSecret(client);
        authenticate(client, tokenEndpoint().requestWithClientCredentialsToken(token, scopes));
    }

    @Test
    void clientCredentialsWorkWithPublicKey() throws Exception {
        Client client = Clients.getAdvancedAuthClient();
        String token = buildTokenFromPrivateKey(client);
        authenticate(client, tokenEndpoint().requestWithClientCredentialsToken(token, scopes));
    }

    private void authenticate(Client client, ValidatableResponse validatableResponse) throws Exception {
        JsonPath tokenResponse = validatableResponse
                .statusCode(200)
                .body(EXPIRES_IN, equalTo(60))
                .body(TOKEN_TYPE, equalToIgnoringCase(TOKEN_TYPE_CONTENT))
                .extract().body().jsonPath();

        assertEquals(scopes, Set.of(tokenResponse.getString(SCOPE).split(" ")));
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ID_TOKEN), client, client);
        tokenAsserter().verifyAccessToken(tokenResponse.getString(ACCESS_TOKEN), client, client);
    }

    private String buildTokenFromSharedSecret(Client client) throws Exception {
        Date now = new Date();
        JWSSigner signer = new MACSigner(client.getPassword().getBytes(StandardCharsets.UTF_8));
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(client.getClientId())
                .issuer(client.getClientId())
                .audience(endpoint.inContainer().getTokenUrl())
                .jwtID("jti")
                .expirationTime(new Date(now.getTime() + 5 * 1000))
                .issueTime(now)
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String buildTokenFromPrivateKey(Client client) throws Exception {
        Date now = new Date();
        JWK jwk = JWK.parseFromPEMEncodedObjects(client.getPublicKey());
        JWSSigner signer = new ECDSASigner(jwk.toECKey());
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(client.getClientId())
                .issuer(client.getClientId())
                .audience(endpoint.inContainer().getTokenUrl())
                .jwtID("jti")
                .expirationTime(new Date(now.getTime() + 5 * 1000))
                .issueTime(now)
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES384), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    @Override
    public Endpoint endpoint() {
        return endpoint;
    }
}
