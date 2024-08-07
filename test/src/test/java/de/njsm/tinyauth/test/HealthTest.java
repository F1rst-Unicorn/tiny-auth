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

import de.njsm.tinyauth.test.repository.Endpoint;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

public class HealthTest implements TinyAuthTest {

    private Endpoint endpoint;

    @Test
    void getHealth() {
        given()
                .log().everything().
        when()
                .get(endpoint().getHealthUrl()).
        then()
                .log().everything()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("ok", equalTo(true));
    }

    @Override
    public Endpoint endpoint() {
        return endpoint;
    }

    @BeforeEach
    void setUp(Endpoint endpoint) {
        this.endpoint = endpoint;
    }
}
