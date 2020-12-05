package de.njsm.tinyauth.test.repository;

public class Endpoints {

    public static String getBaseUri() {
        return "http://localhost:34344/";
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

    public static String getTokenUrl() {
        return getBaseUri() + getTokenPath();
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

}
