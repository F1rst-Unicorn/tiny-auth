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
import de.njsm.tinyauth.test.repository.Endpoints;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;

import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class TokenEndpoint {

    public ValidatableResponse requestWithAuthorizationCodeAndBasicAuth(Client client, String authorizationCode) {
        return request(client, authorizationCode)
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    public ValidatableResponse requestWithAuthorizationCodeAndClientSecretPost(Client client, String authorizationCode) {
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
        return formAuthCodeRequest(client, authorizationCode)
                .auth().preemptive().basic(client.getClientId(), client.getPassword())
                .post()
        .then()
                .log().everything();
    }

    public ValidatableResponse requestWithRefreshToken(Client client, OidcToken refreshToken, Set<String> scopes) {
        return request(client, refreshToken, scopes)
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }

    public ValidatableResponse request(Client client, OidcToken refreshToken, Set<String> scopes) {
        return given()
                .contentType(ContentType.URLENC)
                .formParam(GRANT_TYPE, REFRESH_TOKEN)
                .formParam(REFRESH_TOKEN, refreshToken.getRawToken())
                .formParam(SCOPES, String.join(" ", scopes))
                .formParam(CLIENT_ID, client.getClientId())
                .formParam(CLIENT_SECRET, client.getPassword())
                .post()
        .then()
                .log().everything();
    }

    private RequestSpecification formAuthCodeRequest(Client client, String authorizationCode) {
        return given()
                .contentType(ContentType.URLENC)
                .formParam(ResponseType.CODE.get(), authorizationCode)
                .formParam(GRANT_TYPE, GrantType.AUTHORIZATION_CODE.get())
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
