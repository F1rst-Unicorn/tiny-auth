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

import de.njsm.tinyauth.test.runtime.Browser;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static de.njsm.tinyauth.test.oidc.Identifiers.ERROR;
import static de.njsm.tinyauth.test.oidc.Identifiers.STATE;

public interface MissingNonceFailureTest extends Gadgets {

    @Test
    @Tag("oidcc-basic-certification-test-plan.oidcc-ensure-request-without-nonce-fails")
    @Tag("oidcc-implicit-certification-test-plan.oidcc-ensure-request-without-nonce-fails")
    @Tag("oidcc-hybrid-certification-test-plan.oidcc-ensure-request-without-nonce-fails")
    @Disabled("https://gitlab.com/veenj/tiny-auth/-/issues/68")
    default void authenticateWithoutNonceAndFail(Browser browser) {
        browser.startAuthenticationWithoutNonceGivingError(getClient(), getState(), getScopes());

        HttpUrl oidcRedirect = getLastOidcRedirect(browser);
        assertUrlParameter(oidcRedirect, STATE, getState());
        assertUrlParameter(oidcRedirect, ERROR, "invalid_request");
    }
}
