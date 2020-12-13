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

import de.njsm.tinyauth.test.data.User;
import org.openqa.selenium.By;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthenticationPage extends Page {

    private By username;

    private By password;

    private By submit;

    private By error;

    public AuthenticationPage(FirefoxDriver driver) {
        super(driver);
    }

    @Override
    void initialise() {
        username = By.id("id_username");
        password = By.id("id_password");
        submit = By.id("id_submit");
        error = By.id("error");
    }

    @Override
    void assertDriverIsOnThisPage() {
        waitUntil(ExpectedConditions.presenceOfElementLocated(username));
        assertTrue(driver.findElement(username).isDisplayed(), "field <username> not found");
        assertTrue(driver.findElement(password).isDisplayed(), "field <password> not found");
        assertTrue(driver.findElement(submit).isDisplayed(), "field <submit> not found");
    }

    public AuthenticationPage withUser(User user) {
        withUsername(user.getUsername());
        withPassword(user.getPassword());
        return this;
    }

    public AuthenticationPage withUsername(String username) {
        driver.findElement(this.username).sendKeys(username);
        return this;
    }

    public AuthenticationPage withPassword(String password) {
        driver.findElement(this.password).sendKeys(password);
        return this;
    }

    public AuthorisationPage login() {
        driver.findElement(submit).click();
        return new AuthorisationPage(driver);
    }

    public void loginAndAssumeScopesAreGranted() {
        driver.findElement(submit).click();
        RedirectPage.assertRedirect(driver);
    }
}
