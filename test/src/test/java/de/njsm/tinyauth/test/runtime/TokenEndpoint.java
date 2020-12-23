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

package de.njsm.tinyauth.test.runtime;

import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.repository.Endpoints;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class TokenEndpoint {

    private static final Logger LOG = LogManager.getLogger(TokenEndpoint.class);

    public ValidatableResponse requestWithAuthorizationCodeAndBasicAuth(Client client, String authorizationCode) {
        LOG.info("getting token with authorization code");
        return request(client, authorizationCode)
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    public ValidatableResponse requestWithAuthorizationCodeAndClientSecretPost(Client client, String authorizationCode) {
        LOG.info("getting token with authorization code");
        return formAuthCodeRequest(client, authorizationCode)
                .formParam(CLIENT_SECRET, client.getPassword())
                .post()
        .then()
                .log().everything()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    public ValidatableResponse request(Client client, String authorizationCode) {
        LOG.info("getting token with authorization code");
        return formAuthCodeRequest(client, authorizationCode)
                .auth().preemptive().basic(client.getClientId(), client.getPassword())
                .post()
        .then()
                .log().everything();
    }

    public ValidatableResponse requestWithRefreshToken(Client client, OidcToken refreshToken, Set<String> scopes) {
        LOG.info("getting token with refresh token");
        return request(client, refreshToken, scopes)
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    public ValidatableResponse request(Client client, OidcToken refreshToken, Set<String> scopes) {
        LOG.info("getting token with refresh token");
        return given()
                .contentType(ContentType.URLENC)
                .formParam(GRANT_TYPE, REFRESH_TOKEN)
                .formParam(REFRESH_TOKEN, refreshToken.getRawToken())
                .formParam(SCOPE, String.join(" ", scopes))
                .formParam(CLIENT_ID, client.getClientId())
                .formParam(CLIENT_SECRET, client.getPassword())
                .post()
        .then()
                .log().everything();
    }

    public ValidatableResponse requestWithClientCredentials(Client client, Set<String> scopes) {
        LOG.info("getting token with client credentials");
        return given()
                .auth().preemptive().basic(client.getClientId(), client.getPassword())
                .contentType(ContentType.URLENC)
                .formParam(GRANT_TYPE, CLIENT_CREDENTIALS)
                .formParam(SCOPE, String.join(" ", scopes))
                .post()
        .then()
                .log().everything();
    }

    public ValidatableResponse requestWithClientCredentialsToken(String token, Set<String> scopes) {
        LOG.info("getting token with client credentials token");
        return given()
                .contentType(ContentType.URLENC)
                .formParam(GRANT_TYPE, CLIENT_CREDENTIALS)
                .formParam(SCOPE, String.join(" ", scopes))
                .formParam(CLIENT_ASSERTION, token)
                .formParam(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_VALUE)
                .post()
        .then()
                .log().everything();
    }

    public ValidatableResponse requestWithPassword(Client client, User user, Set<String> scopes) {
        LOG.info("getting token with password");
        return requestWithPassword(client, user, user.getPassword(), scopes);
    }

    public ValidatableResponse requestWithPassword(Client client, User user, String password, Set<String> scopes) {
        LOG.info("getting token with password");
        return given()
                .auth().preemptive().basic(client.getClientId(), client.getPassword())
                .contentType(ContentType.URLENC)
                .formParam(GRANT_TYPE, PASSWORD)
                .formParam(USERNAME, user.getUsername())
                .formParam(PASSWORD, password)
                .formParam(SCOPE, String.join(" ", scopes))
                .post()
        .then()
                .log().everything();
    }

    private RequestSpecification formAuthCodeRequest(Client client, String authorizationCode) {
        return given()
                .contentType(ContentType.URLENC)
                .formParam(ResponseType.CODE.get(), authorizationCode)
                .formParam(GRANT_TYPE, AUTHORIZATION_CODE)
                .formParam(REDIRECT_URI, client.getRedirectUri())
                .formParam(CLIENT_ID, client.getClientId());
    }

    private RequestSpecification given() {
        return RestAssured.given()
                .log().everything()
                .baseUri(Endpoints.getTokenUrl())
        .when();
    }
}
