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

import de.njsm.tinyauth.test.repository.Endpoints;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;

public class DiscoveryTest implements TinyAuthTest {

    @Test
    void verifyDiscoverySettings() {
        given()
                .log().everything().
        when()
                .get(Endpoints.getDiscoveryUrl()).
        then()
                .log().everything()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("issuer", equalTo(Endpoints.getIssuer()))
                .body("authorization_endpoint", equalTo(Endpoints.getAuthorizationUrl()))
                .body("token_endpoint", equalTo(Endpoints.getTokenUrl()))
                .body("userinfo_endpoint", equalTo(Endpoints.getUserinfoUrl()))
                .body("jwks_uri", equalTo(Endpoints.getJwksUrl()))
                .body("scopes_supported", containsInAnyOrder("openid", "email", "profile", "phone", "address"))
                .body("response_types_supported", containsInAnyOrder("code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"))
                .body("grant_types_supported", containsInAnyOrder("authorization_code", "implicit", "client_credentials", "password", "refresh_token"))
                .body("subject_types_supported", containsInAnyOrder("public"))
                .body("id_token_signing_alg_values_supported", containsInAnyOrder("HS256", "HS384", "HS512", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"))
                .body("token_endpoint_auth_methods_supported", containsInAnyOrder("client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"))
                .body("claims_supported", containsInAnyOrder("iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp"))
                .body("service_documentation", equalTo("https://gitlab.com/veenj/tiny-auth/-/blob/master/doc/README.md"))
                .body("claims_locales_supported", containsInAnyOrder("en"))
                .body("ui_locales_supported", containsInAnyOrder("en"))
                .body("claims_parameter_supported", equalTo(false))
                .body("request_parameter_supported", equalTo(false))
                .body("request_uri_parameter_supported", equalTo(false))
                .body("require_request_uri_registration", equalTo(false));
    }
}
