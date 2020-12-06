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
import de.njsm.tinyauth.test.runtime.webpage.AuthenticationPage;
import okhttp3.HttpUrl;
import org.jetbrains.annotations.NotNull;
import org.openqa.selenium.firefox.FirefoxDriver;

import java.util.Map;
import java.util.Set;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class Browser {

    private final FirefoxDriver driver;

    public Browser(FirefoxDriver driver) {
        this.driver = driver;
    }

    public AuthenticationPage startAuthentication(Client client, String state, Set<String> scopes, String nonce) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce);
        driver.navigate().to(url.url());
        return new AuthenticationPage(driver);
    }

    public AuthenticationPage startAuthenticationWithAdditionalParameters(Client client, String state, Set<String> scopes, String nonce, Map<String, String> additionalParameters) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce);

        HttpUrl.Builder builder = url.newBuilder();
        additionalParameters.forEach(builder::addQueryParameter);
        url = builder.build();

        driver.navigate().to(url.url());
        return new AuthenticationPage(driver);
    }

    public void startAuthenticationWithMissingResponseType(Client client, String state, Set<String> scopes, String nonce) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce)
                .newBuilder()
                .removeAllQueryParameters(RESPONSE_TYPE)
                .build();

        driver.navigate().to(url.url());
    }

    public AuthenticationPage startAuthenticationWithoutNonce(Client client, String state, Set<String> scopes) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, "")
                .newBuilder()
                .removeAllQueryParameters(NONCE)
                .build();

        driver.navigate().to(url.url());
        return new AuthenticationPage(driver);
    }

    @NotNull
    private HttpUrl generateUrlForHappyPath(Client client, String state, Set<String> scopes, String nonce) {
        return HttpUrl.get(Endpoints.getAuthorizationUrl())
                .newBuilder()
                .addQueryParameter(CLIENT_ID, client.getClientId())
                .addQueryParameter(STATE, state)
                .addQueryParameter(NONCE, nonce)
                .addQueryParameter(SCOPE, String.join(" ", scopes))
                .addQueryParameter(RESPONSE_TYPE, ResponseType.CODE.get())
                .addQueryParameter(REDIRECT_URI, client.getRedirectUri())
                .build();
    }
}
