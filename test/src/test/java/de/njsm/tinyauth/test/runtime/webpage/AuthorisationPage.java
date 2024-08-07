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

package de.njsm.tinyauth.test.runtime.webpage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthorisationPage extends Page {

    private static final Logger LOG = LogManager.getLogger(AuthorisationPage.class);

    private By submit;

    public AuthorisationPage(RemoteWebDriver driver) {
        super(driver);
    }

    @Override
    void initialise() {
        submit = By.id("id_submit");
    }

    @Override
    void assertDriverIsOnThisPage() {
        waitUntil(ExpectedConditions.presenceOfElementLocated(submit));
        assertTrue(driver.findElement(submit).isDisplayed(), "field <submit> not found");
        LOG.info("on this page");
    }

    public AuthorisationPage toggleScope(String scope) {
        driver.findElement(By.name(scope)).click();
        return this;
    }

    public void confirm() {
        driver.findElement(submit).click();
        RedirectPage.assertRedirect(driver);
    }
}
