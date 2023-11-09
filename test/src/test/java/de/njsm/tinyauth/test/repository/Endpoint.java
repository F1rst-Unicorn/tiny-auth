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

public record Endpoint(String host, int port) {

    public Endpoint inContainer() {
        return new Endpoint("tiny-auth", 34344);
    }

    public String getBaseUri() {
        return "https://" + host + ":" + port;
    }

    public String getIssuer() {
        return getBaseUri();
    }

    public String getAuthorizationUrl() {
        return getBaseUri() + getAuthorizationPath();
    }

    public String getJwksUrl() {
        return getBaseUri() + getJwksPath();
    }

    public String getHealthUrl() {
        return getBaseUri() + getHealthPath();
    }

    public String getDiscoveryUrl() {
        return getBaseUri() + getDiscoveryPath();
    }

    public String getTokenUrl() {
        return getBaseUri() + getTokenPath();
    }

    public String getUserinfoUrl() {
        return getBaseUri() + getUserinfoPath();
    }

    private static String getUserinfoPath() {
        return "/userinfo";
    }

    private static String getDiscoveryPath() {
        return "/.well-known/openid-configuration";
    }

    private static String getTokenPath() {
        return "/token";
    }

    private static String getAuthorizationPath() {
        return "/authorize";
    }

    private static String getJwksPath() {
        return "/jwks";
    }

    private static String getHealthPath() {
        return "/health";
    }
}
