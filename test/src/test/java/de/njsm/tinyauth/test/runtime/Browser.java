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
import de.njsm.tinyauth.test.runtime.webpage.AuthorisationPage;
import de.njsm.tinyauth.test.runtime.webpage.InvalidRedirectUriPage;
import de.njsm.tinyauth.test.runtime.webpage.RedirectPage;
import okhttp3.HttpUrl;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.firefox.FirefoxDriver;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static de.njsm.tinyauth.test.oidc.Identifiers.*;

public class Browser {

    private static final Logger LOG = LogManager.getLogger(Browser.class);

    private final FirefoxDriver driver;

    private Set<ResponseType> responseType;

    public Browser(FirefoxDriver driver) {
        this.driver = driver;
    }

    public void setResponseType(Set<ResponseType> responseTypes) {
        this.responseType = responseTypes;
    }

    public void resetCookies() {
        driver.manage().deleteAllCookies();
    }

    public AuthenticationPage startAuthentication(Client client, String state, Set<String> scopes, String nonce) {
        return startAuthenticationWithAdditionalParameters(client, state, scopes, nonce, Collections.emptyMap());
    }

    public AuthenticationPage startAuthenticationWithAdditionalParameters(Client client, String state, Set<String> scopes, String nonce, Map<String, String> additionalParameters) {
        startAuthentication(client, state, scopes, nonce, additionalParameters);
        return new AuthenticationPage(driver);
    }

    public AuthorisationPage startAuthenticationWithConsent(Client client, String state, Set<String> scopes, String nonce, Map<String, String> additionalParameters) {
        startAuthentication(client, state, scopes, nonce, additionalParameters);
        return new AuthorisationPage(driver);
    }

    public void startAuthenticationWithoutInteraction(Client client, String state, Set<String> scopes, String nonce, Map<String, String> additionalParameters) {
        startAuthentication(client, state, scopes, nonce, additionalParameters);
        RedirectPage.assertRedirect(driver);
    }

    private void startAuthentication(Client client, String state, Set<String> scopes, String nonce, Map<String, String> additionalParameters) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce);

        HttpUrl.Builder builder = url.newBuilder();
        additionalParameters.forEach(builder::addQueryParameter);
        url = builder.build();

        LOG.info("Going to " + url.url());
        driver.navigate().to(url.url());
    }

    public void startAuthenticationWithMissingResponseType(Client client, String state, Set<String> scopes, String nonce) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce)
                .newBuilder()
                .removeAllQueryParameters(RESPONSE_TYPE)
                .build();

        LOG.info("Going to " + url.url());
        driver.navigate().to(url.url());
        RedirectPage.assertRedirect(driver);
    }

    public AuthenticationPage startAuthenticationWithoutNonce(Client client, String state, Set<String> scopes) {
        startAuthenticationWithoutNonceGivingError(client, state, scopes);
        return new AuthenticationPage(driver);
    }

    public void startAuthenticationWithoutNonceGivingError(Client client, String state, Set<String> scopes) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, "")
                .newBuilder()
                .removeAllQueryParameters(NONCE)
                .build();

        LOG.info("Going to " + url.url());
        driver.navigate().to(url.url());
    }

    public void startAuthenticationWithInvalidRedirectUri(Client client, String state, Set<String> scopes, String nonce, String redirectUri) {
        HttpUrl url = generateUrlForHappyPath(client, state, scopes, nonce)
                .newBuilder()
                .removeAllQueryParameters(REDIRECT_URI)
                .addQueryParameter(REDIRECT_URI, redirectUri)
                .build();

        LOG.info("Going to " + url.url());
        driver.navigate().to(url.url());
        InvalidRedirectUriPage.assertShown(driver);
    }

    HttpUrl generateUrlForHappyPath(Client client, String state, Set<String> scopes, String nonce) {
        return HttpUrl.get(Endpoints.getAuthorizationUrl())
                .newBuilder()
                .addQueryParameter(CLIENT_ID, client.getClientId())
                .addQueryParameter(STATE, state)
                .addQueryParameter(NONCE, nonce)
                .addQueryParameter(SCOPE, String.join(" ", scopes))
                .addQueryParameter(RESPONSE_TYPE, responseType.stream().map(ResponseType::get).collect(Collectors.joining(" ")))
                .addQueryParameter(REDIRECT_URI, client.getRedirectUri())
                .build();
    }

    public String getCurrentlUrl() {
        return driver.getCurrentUrl();
    }
}
