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

import de.njsm.tinyauth.test.oidc.TokenAsserter;
import de.njsm.tinyauth.test.runtime.SeleniumLifecycleManager;
import de.njsm.tinyauth.test.runtime.TokenEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.MediaType;
import org.mockserver.model.RequestDefinition;

import java.security.SecureRandom;
import java.util.Base64;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = {34345})
@ExtendWith(SeleniumLifecycleManager.class)
public class TinyAuthBrowserTest implements TinyAuthTest {

    private String state;

    private String nonce;

    private MockServerClient mockServerClient;

    @BeforeEach
    public void resetMockServer(MockServerClient client) {
        client.reset();
        client.when(
                request().withPath("/redirect/.*")
        ).respond(
                response()
                        .withStatusCode(200)
                        .withContentType(MediaType.HTML_UTF_8)
                        .withBody("<!doctype html>" +
                                "<html>" +
                                "<head>" +
                                "<meta charset=\"UTF-8\">" +
                                "</head>" +
                                "<body>" +
                                "<h1 id=\"result\">Hello World!</h1>" +
                                "</body>" +
                                "</html>")
        );
        mockServerClient = client;
    }

    @BeforeEach
    public void initialiseRandomness() {
        byte[] randomness = new byte[16];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(randomness);
        state = Base64.getEncoder().encodeToString(randomness);
        rng.nextBytes(randomness);
        nonce = Base64.getEncoder().encodeToString(randomness);
    }

    String getStateParameter() {
        return state;
    }

    String getNonceParameter() {
        return nonce;
    }

    TokenEndpoint tokenEndpoint() {
        return new TokenEndpoint();
    }

    TokenAsserter tokenAsserter() {
        return new TokenAsserter();
    }

    HttpRequest getLastOidcRedirect() {
        RequestDefinition[] requests = mockServerClient.retrieveRecordedRequests(request().withPath("/redirect/.*").withMethod("GET"));
        return (HttpRequest) requests[requests.length - 1];
    }
}
