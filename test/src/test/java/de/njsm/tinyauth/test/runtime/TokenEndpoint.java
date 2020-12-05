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
import de.njsm.tinyauth.test.repository.Endpoints;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class TokenEndpoint {

    public ValidatableResponse requestWithAuthorizationCodeAndBasicAuth(Client client, String authorizationCode) {
        return RestAssured.given()
                .log().everything()
                .baseUri(Endpoints.getTokenUrl())
        .when()
                .auth().preemptive().basic(client.getClientId(), client.getPassword())
                .contentType(ContentType.URLENC)
                .formParam(ResponseType.CODE.get(), authorizationCode)
                .formParam(GRANT_TYPE, GrantType.AUTHORIZATION_CODE.get())
                .formParam(REDIRECT_URI, client.getRedirectUri())
                .formParam(CLIENT_ID, client.getClientId())
                .post()
        .then()
                .log().everything()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache");
    }
}
