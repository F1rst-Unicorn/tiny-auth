package de.njsm.tinyauth.test.runtime;

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static io.restassured.config.ConnectionConfig.connectionConfig;

public class RestAssuredConfiguration implements BeforeAllCallback {
    @Override
    public void beforeAll(ExtensionContext context) {
        RestAssured.config = RestAssuredConfig.config()
                .connectionConfig(connectionConfig().closeIdleConnectionsAfterEachResponse());
    }
}
