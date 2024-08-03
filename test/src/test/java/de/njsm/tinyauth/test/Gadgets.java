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
import de.njsm.tinyauth.test.data.OidcToken;
import de.njsm.tinyauth.test.data.Tokens;
import de.njsm.tinyauth.test.data.User;
import de.njsm.tinyauth.test.oidc.Identifiers;
import de.njsm.tinyauth.test.oidc.TokenAsserter;
import de.njsm.tinyauth.test.oidc.TokenAsserterWithNonce;
import de.njsm.tinyauth.test.oidc.redirect.RedirectExtractor;
import de.njsm.tinyauth.test.repository.Endpoint;
import de.njsm.tinyauth.test.runtime.Browser;
import okhttp3.HttpUrl;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

public interface Gadgets extends TinyAuthTest, RedirectExtractor, ApiGadgets {

    Tokens authenticate(Browser browser) throws Exception;

    Tokens authenticate(Browser browser, Set<String> scopes) throws Exception;

    Tokens authenticateWithAdditionalParameters(Browser browser, Map<String, String> scopes) throws Exception;

    OidcToken selectToken(Tokens tokens);

    String getState();

    String getNonce();

    User getUser();

    Client getClient();

    Set<String> getScopes();

    Endpoint endpoint();

    default void assertUrlParameter(HttpUrl oidcRedirect, String key, String value) {
        assertTrue(oidcRedirect.queryParameterValues(key).contains(value),
                key + " was '" + oidcRedirect.queryParameter(key) + "', expected '" + value + "'");
    }

    default TokenAsserter tokenAsserter() {
        return new TokenAsserterWithNonce(endpoint(), getNonce());
    }

    Set<Identifiers.ResponseType> getResponseTypes();
}
