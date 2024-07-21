/*
 * tiny-auth: Tiny OIDC Provider
 * Copyright (C) 2019 The tiny-auth developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { ApiService } from "./api/api.ts";
import { UserStoreImpl } from "./storage/auth-store.ts";
import { AuthProviderProps } from "react-oidc-context";
import { WebStorageStateStore } from "oidc-client-ts";
import { Interactor } from "./core/changePassword.ts";

const redirectPath = "/oidc-login-redirect";

function resolveAuthority() {
  if (import.meta.env.MODE === "development") {
    return {
      authority: "http://localhost:34344",
      redirect_uri: "http://localhost:5173" + redirectPath,
      silent_redirect_uri: "http://localhost:5173/oidc-login-redirect-silent"
    };
  } else {
    let oidcAuthority = document
      .getElementById("tiny-auth-provider")
      ?.getAttribute("href");
    if (oidcAuthority === null || oidcAuthority === undefined)
      oidcAuthority = "";

    return {
      authority: oidcAuthority,
      redirect_uri: oidcAuthority + redirectPath,
      silent_redirect_uri: oidcAuthority + "/oidc-login-redirect-silent"
    };
  }
}

export const oidcConfiguration: AuthProviderProps = {
  ...resolveAuthority(),
  client_id: "tiny-auth-frontend",
  scope: "openid profile",
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  accessTokenExpiringNotificationTimeInSeconds: 5,
  onSigninCallback: () => {
    console.log("onSigninCallback from " + window.location.href);
    window.history.replaceState({}, document.title, window.location.pathname);
    if (window.location.pathname === redirectPath) {
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname.replace(new RegExp(redirectPath + "$"), "/")
      );
    }
  }
};

function resolveApi(): string {
  if (import.meta.env.MODE === "development") {
    return "http://localhost:8089";
  } else {
    let auth = document.getElementById("tiny-auth-api")?.getAttribute("href");
    if (auth === null || auth === undefined) auth = "";

    return auth;
  }
}

const userStore = new UserStoreImpl(
  oidcConfiguration.authority,
  oidcConfiguration.client_id
);

const apiClient = new ApiService(resolveApi(), userStore);
export const changePasswordInteractor = new Interactor(apiClient);
