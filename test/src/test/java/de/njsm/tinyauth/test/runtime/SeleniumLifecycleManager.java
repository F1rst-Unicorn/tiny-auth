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

import de.njsm.tinyauth.test.repository.Endpoints;
import org.junit.jupiter.api.extension.*;
import org.junit.jupiter.api.extension.support.TypeBasedParameterResolver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.virtualauthenticator.Credential;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;

import java.io.File;

public class SeleniumLifecycleManager extends TypeBasedParameterResolver<Browser> implements BeforeAllCallback, AfterAllCallback, BeforeEachCallback {

    private FirefoxDriver driver;

    private Browser browser;

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        FirefoxProfile profile = new FirefoxProfile(new File(Config.getProfilePath()));
        profile.setPreference("intl.accept_languages", "de");
        profile.setPreference("security.default_personal_cert", "Select Automatically");
        FirefoxOptions options = new FirefoxOptions();
        options.setHeadless(true);
        options.setProfile(profile);
        driver = new FirefoxDriver(options);
        //VirtualAuthenticator authenticator = driver.addVirtualAuthenticator(buildVirtualAuthenticator());
        //authenticator.setUserVerified(true);
        //authenticator.addCredential(buildCredential());
        browser = new Browser(driver, null);
    }

    private VirtualAuthenticatorOptions buildVirtualAuthenticator() {
        return new VirtualAuthenticatorOptions()
                .setTransport(VirtualAuthenticatorOptions.Transport.USB)
                .setProtocol(VirtualAuthenticatorOptions.Protocol.U2F)
                .setHasUserVerification(false)
                .setHasResidentKey(false)
                .setIsUserConsenting(true)
                .setIsUserVerified(true);
    }

    private Credential buildCredential() {
        return Credential.createNonResidentCredential(new byte[]{1}, Endpoints.getIssuer(), null, 0);
    }

    @Override
    public void afterAll(ExtensionContext extensionContext) {
        driver.quit();
    }

    @Override
    public void beforeEach(ExtensionContext extensionContext) {
        browser.resetCookies();
    }

    @Override
    public Browser resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return browser;
    }
}
