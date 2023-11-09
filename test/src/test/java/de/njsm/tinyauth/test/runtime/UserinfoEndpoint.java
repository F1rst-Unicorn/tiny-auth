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

import de.njsm.tinyauth.test.repository.Endpoint;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static de.njsm.tinyauth.test.oidc.Identifiers.ACCESS_TOKEN;
import static de.njsm.tinyauth.test.oidc.Identifiers.TOKEN_TYPE_CONTENT;

public class UserinfoEndpoint {

    private static final Logger LOG = LogManager.getLogger(UserinfoEndpoint.class);

    private final Endpoint endpoint;

    public UserinfoEndpoint(Endpoint endpoint) {
        this.endpoint = endpoint;
    }

    public JsonPath getUserinfo(String accessToken) {
        LOG.info("getting userinfo");
        return verifyBasics(when()
                .header("Authorization", TOKEN_TYPE_CONTENT + " " + accessToken)
                .get());
    }

    public JsonPath postUserinfo(String accessToken) {
        LOG.info("posting userinfo");
        return verifyBasics(when()
                .header("Authorization", TOKEN_TYPE_CONTENT + " " + accessToken)
                .post());
    }

    public JsonPath postUserinfoWithTokenInBody(String accessToken) {
        LOG.info("posting userinfo");
        return verifyBasics(when()
                .contentType(ContentType.URLENC)
                .formParam(ACCESS_TOKEN, accessToken)
                .post());
    }

    private RequestSpecification when() {
        return RestAssured.given()
                .log().everything()
                .baseUri(endpoint.getUserinfoUrl())
                .when();
    }

    private JsonPath verifyBasics(Response response) {
        return response.then()
                .log().everything()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .extract().jsonPath();
    }
}
