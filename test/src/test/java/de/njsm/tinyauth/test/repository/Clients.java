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

package de.njsm.tinyauth.test.repository;

import de.njsm.tinyauth.test.data.Client;

public class Clients {
    public static Client getConfidentialClient() {
        return new Client("confidential", "password", "http://localhost:34345/redirect/confidential");
    }

    public static Client getClientForNoPromptTest() {
        return new Client("client-for-no-prompt-test", "password", "http://localhost:34345/redirect/client-for-no-prompt-test");
    }

    public static Client getClientForTokenSwitchAttack() {
        return new Client("needed-for-token-switch-attack", "password", "http://localhost:34345/redirect/needed-for-token-switch-attack");
    }

    public static Client getAdvancedAuthClient() {
        return new Client("advanced-client-auth", "passwordpasswordpasswordpasswordpasswordpassword",
                "http://localhost:34345/redirect/advanced-client-auth",
                "-----BEGIN PRIVATE KEY-----\n" +
                "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDcQ4w1qyBpSr7kHk7M\n" +
                "lK6tEOBDE0gTozttlqB6qW71JcfhGp7YxECP13XUa/XfkNuhZANiAARfBFqROixP\n" +
                "tsrlgQ5GVCMvOkd6GS4sMS7/SkXZrFsfIAZq0PZAJ/Qp+a7KUGV2jJqlKPyYJjXU\n" +
                "Se+nShnhLWRiZuF+AgTBfXq4OQqsyxpN4j+22+BHTXHMx89fKMDgh+w=\n" +
                "-----END PRIVATE KEY-----\n" +
                "-----BEGIN PUBLIC KEY-----\n" +
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXwRakTosT7bK5YEORlQjLzpHehkuLDEu\n" +
                "/0pF2axbHyAGatD2QCf0KfmuylBldoyapSj8mCY11Envp0oZ4S1kYmbhfgIEwX16\n" +
                "uDkKrMsaTeI/ttvgR01xzMfPXyjA4Ifs\n" +
                "-----END PUBLIC KEY-----\n");
    }

    public static Client getPublicClient() {
        return new Client("public", "", "http://localhost:34345/redirect/public");
    }

    public static Client getRestrictedScopeClient() {
        return new Client("restricted-scopes", "password", "http://localhost:34345/redirect/restricted-scopes");
    }
}
