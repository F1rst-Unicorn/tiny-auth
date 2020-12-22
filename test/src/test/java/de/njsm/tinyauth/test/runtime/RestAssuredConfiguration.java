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

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static io.restassured.config.ConnectionConfig.connectionConfig;
import static io.restassured.config.SSLConfig.sslConfig;

public class RestAssuredConfiguration implements BeforeAllCallback {
    @Override
    public void beforeAll(ExtensionContext context) {
        RestAssured.config = RestAssuredConfig.config()
                .connectionConfig(connectionConfig().closeIdleConnectionsAfterEachResponse())
                .sslConfig(sslConfig()
                        .keyStore(System.getProperty("javax.net.ssl.keyStore"),
                                System.getProperty("javax.net.ssl.keyStorePassword"))
                        .keystoreType(System.getProperty("javax.net.ssl.keyStoreType"))
                        .trustStore(System.getProperty("javax.net.ssl.trustStore"),
                                System.getProperty("javax.net.ssl.trustStorePassword"))
                        .trustStoreType(System.getProperty("javax.net.ssl.trustStoreType"))
                );
    }
}
