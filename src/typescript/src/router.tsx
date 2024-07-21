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

import { createBrowserRouter } from "react-router-dom";
import ErrorPage from "./errorPage.tsx";
import Root from "./root.tsx";
import Index from "./components/Index.tsx";
import Profile from "./components/Profile.tsx";
import { oidcConfiguration } from "./constructor.ts";
import { AuthProvider } from "react-oidc-context";
import { changePasswordAction } from "./components/actions/changePassword.ts";

function resolveWebBase(): string {
  if (import.meta.env.MODE === "development") {
    return "";
  } else {
    let webBase = document
      .getElementById("tiny-auth-web-base")
      ?.getAttribute("href");
    if (webBase === null || webBase === undefined) webBase = "";
    return webBase;
  }
}

export const webBase = resolveWebBase();

export const router = createBrowserRouter([
  {
    path: webBase,
    element: <Root />,
    errorElement: <ErrorPage />,
    children: [
      {
        errorElement: <ErrorPage />,
        children: [
          {
            index: true,
            element: <Index />
          },
          {
            path: "profile",
            element: <Profile />
          },
          {
            path: "oidc-login-redirect",
            element: <Index />
          },
          {
            path: "oidc-login-redirect-silent",
            element: <AuthProvider {...oidcConfiguration} />
          },
          {
            path: "api",
            children: [
              {
                path: "changePassword",
                action: changePasswordAction
              }
            ]
          }
        ]
      }
    ]
  }
]);
