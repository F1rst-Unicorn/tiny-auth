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

public class Endpoints {

    public static String getBaseUri() {
        return "https://localhost:34344/";
    }

    public static String getIssuer() {
        String result = getBaseUri();
        result = result.substring(0, result.length() - 1);
        return result;
    }

    public static String getAuthorizationUrl() {
        return getBaseUri() + getAuthorizationPath();
    }

    public static String getJwksUrl() {
        return getBaseUri() + getJwksPath();
    }

    public static String getHealthUrl() {
        return getBaseUri() + getHealthPath();
    }

    public static String getDiscoveryUrl() {
        return getBaseUri() + getDiscoveryPath();
    }

    public static String getTokenUrl() {
        return getBaseUri() + getTokenPath();
    }

    public static String getUserinfoUrl() {
        return getBaseUri() + getUserinfoPath();
    }

    public static String getU2fUrl() {
        return getBaseUri() + getU2fPath();
    }

    private static String getUserinfoPath() {
        return "userinfo";
    }

    private static String getDiscoveryPath() {
        return ".well-known/openid-configuration";
    }

    private static String getTokenPath() {
        return "token";
    }

    private static String getAuthorizationPath() {
        return "authorize";
    }

    public static String getJwksPath() {
        return "jwks";
    }

    public static String getHealthPath() {
        return "health";
    }

    private static String getU2fPath() {
        return "u2f";
    }
}
