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

package de.njsm.tinyauth.test.oidc;

public class Identifiers {

    public static final String CLIENT_ID = "client_id";

    public static final String CLIENT_SECRET = "client_secret";

    public static final String STATE = "state";

    public static final String ERROR = "error";

    public static final String ERROR_DESCRIPTION = "error_description";

    public static final String NONCE = "nonce";

    public static final String ISSUER = "iss";

    public static final String AUTHORIZED_PARTY = "azp";

    public static final String SUBJECT = "sub";

    public static final String EXPIRATION_TIME = "exp";

    public static final String ISSUANCE_TIME = "iat";

    public static final String AUDIENCE = "aud";

    public static final String AUTH_TIME = "auth_time";

    public static final String SCOPE = "scope";

    public static final String SCOPES = "scopes";

    public static final String REDIRECT_URI = "redirect_uri";

    public static final String RESPONSE_TYPE = "response_type";

    public static final String TOKEN_TYPE = "token_type";

    public static final String TOKEN_TYPE_CONTENT = "Bearer";

    public static final String EXPIRES_IN = "expires_in";

    public static final String GRANT_TYPE = "grant_type";

    public static final String ACCESS_TOKEN = "access_token";

    public static final String REFRESH_TOKEN = "refresh_token";

    public static final String CLIENT_CREDENTIALS = "client_credentials";

    public static final String ID_TOKEN = "id_token";

    public static final String INVALID_GRANT = "invalid_grant";

    public static final String ACCESS_DENIED = "access_denied";

    public static final String USERNAME = "username";

    public static final String PASSWORD = "password";

    public static final String AUTHORIZATION_CODE = "authorization_code";

    public static final String CLIENT_ASSERTION = "client_assertion";

    public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";

    public static final String CLIENT_ASSERTION_TYPE_VALUE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public static final String CODE_CHALLENGE = "code_challenge";

    public static final String CODE_VERIFIER = "code_verifier";

    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";

    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    public enum ResponseType {
        ID_TOKEN {
            @Override
            public String get() {
                return "id_token";
            }
        },

        TOKEN {
            @Override
            public String get() {
                return "token";
            }
        },

        CODE {
            @Override
            public String get() {
                return "code";
            }
        };

        public abstract String get();
    }


}
