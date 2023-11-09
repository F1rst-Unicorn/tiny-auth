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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.*;
import org.junit.jupiter.api.extension.support.TypeBasedParameterResolver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.testcontainers.containers.BrowserWebDriverContainer;
import org.testcontainers.containers.NginxContainer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.lifecycle.Startables;

import java.io.File;

public class SeleniumLifecycleManager extends TypeBasedParameterResolver<Browser> implements BeforeAllCallback, BeforeEachCallback, ExtensionContext.Store.CloseableResource{

    private static final Logger LOG = LogManager.getLogger(SeleniumLifecycleManager.class);

    public static final String REDIRECT_PAGE = "<!doctype html>" +
            "<html>" +
            "<head>" +
            "<meta charset=\"UTF-8\">" +
            "</head>" +
            "<body>" +
            "<h1 id=\"result\">Hello World!</h1>" +
            "</body>" +
            "</html>";
    private BrowserWebDriverContainer<?> seleniumContainer;

    private NginxContainer<?> nginxContainer;

    private RemoteWebDriver driver;

    private Browser browser;

    private boolean started = false;

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        if (started) {
            return;
        }

        extensionContext.getStore(ExtensionContext.Namespace.create(extensionContext.getRequiredTestClass()))
                .put(this.getClass().getCanonicalName(), this);
        UutLifecycleManager uut = extensionContext.getStore(
                ExtensionContext.Namespace.create(extensionContext.getRequiredTestClass())).get(
                UutLifecycleManager.class.getCanonicalName(),
                UutLifecycleManager.class);
        FirefoxProfile profile = new FirefoxProfile(new File(Config.getRoot() + "/test/src/test/resources/firefox"));
        profile.setPreference("intl.accept_languages", "de");
        profile.setPreference("security.default_personal_cert", "Select Automatically");
        FirefoxOptions options = new FirefoxOptions();
        options.setHeadless(true);
        options.setProfile(profile);
        seleniumContainer = new BrowserWebDriverContainer<>()
                .withNetworkAliases("browser")
                .withNetwork(uut.network())
                .withCapabilities(options)
                .withRecordingMode(BrowserWebDriverContainer.VncRecordingMode.SKIP, null);
        nginxContainer = new NginxContainer<>()
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/restricted-scopes.html")
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/public.html")
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/needed-for-token-switch-attack.html")
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/confidential.html")
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/client-for-no-prompt-test.html")
                .withCopyToContainer(Transferable.of(REDIRECT_PAGE), "/usr/share/nginx/html/redirect/advanced-client-auth.html")
                .withNetworkAliases("client")
                .withNetwork(uut.network())
                .waitingFor(new HttpWaitStrategy());

        Startables.deepStart(seleniumContainer, nginxContainer).join();
        driver = new RemoteWebDriver(seleniumContainer.getSeleniumAddress(), options);
        browser = new Browser(driver, uut.endpoint());
    }

    @Override
    public void close() {
        nginxContainer.close();
        driver.quit();
        seleniumContainer.close();
        started = false;
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
