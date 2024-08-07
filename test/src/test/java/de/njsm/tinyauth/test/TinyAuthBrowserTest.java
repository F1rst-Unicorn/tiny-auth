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

import de.njsm.tinyauth.test.data.Client;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.oidc.Identifiers;
import de.njsm.tinyauth.test.repository.Endpoint;
import de.njsm.tinyauth.test.repository.Users;
import de.njsm.tinyauth.test.runtime.Browser;
import de.njsm.tinyauth.test.runtime.SeleniumLifecycleManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SeleniumLifecycleManager.class)
public abstract class TinyAuthBrowserTest implements TinyAuthTest {

    private String state;

    private String nonce;

    private String codeVerifier;

    private Endpoint endpoint;

    User user;

    Client client;

    Set<String> scopes;

    @BeforeEach
    public void configureBrowser(Browser browser) {
        browser.setResponseType(getResponseTypes());
    }

    @BeforeEach
    public void initialiseRandomness() {
        byte[] randomness = new byte[16];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(randomness);
        state = "+" + Base64.getEncoder().encodeToString(randomness);
        rng.nextBytes(randomness);
        nonce = Base64.getEncoder().encodeToString(randomness);
        randomness = new byte[32];
        rng.nextBytes(randomness);
        String string = Base64.getEncoder().withoutPadding().encodeToString(randomness);
        assertTrue(string.length() >= 43, "code verifier is too short, 43 <= n <= 128");
        codeVerifier = string
                .replace("/", "a")
                .replace("+", "b")
                .substring(0, Math.min(string.length(), 128));
    }

    @BeforeEach
    public void setEndpoint(Endpoint endpoint) {
        this.endpoint = endpoint;
    }

    @BeforeEach
    public void setupParameters() {
        user = Users.getUser();
        scopes = Set.of("openid");
    }

    public String getState() {
        return state;
    }

    public String getNonce() {
        return nonce;
    }

    public User getUser() {
        return user;
    }

    public Client getClient() {
        return client;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public abstract Set<Identifiers.ResponseType> getResponseTypes();

    public String getCodeVerifier() {
        return codeVerifier;
    }

    @Override
    public Endpoint endpoint() {
        return endpoint;
    }
}
