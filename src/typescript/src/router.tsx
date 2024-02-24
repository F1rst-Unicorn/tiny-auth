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
            element: <Index />,
          },
          {
            path: "profile",
            element: <Profile />,
          },
          {
            path: "oidc-login-redirect",
            element: <Index />,
          },
          {
            path: "oidc-login-redirect-silent",
            element: <AuthProvider {...oidcConfiguration} />,
          },
          {
            path: "api",
            children: [
              {
                path: "changePassword",
                action: changePasswordAction,
              },
            ],
          },
        ],
      },
    ],
  },
]);
