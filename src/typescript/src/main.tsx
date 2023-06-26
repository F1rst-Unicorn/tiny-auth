import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import {AuthProvider, AuthProviderProps} from "react-oidc-context";
import {User} from "oidc-client-ts";
import {createBrowserRouter, RouterProvider} from "react-router-dom";

const oidcAuthority = resolveAuthority();
const oidcConfigurationBase = import.meta.env.MODE === "development" ? {
    authority: "http://localhost:34344",
    redirect_uri: "http://localhost:5173/oidc-login-redirect",
    silent_redirect_uri: "http://localhost:5173/oidc-login-redirect-silent.html",
} : {
    authority: oidcAuthority,
    redirect_uri: oidcAuthority + "/oidc-login-redirect",
    silent_redirect_uri: oidcAuthority + "/oidc-login-redirect-silent",
};

const oidcConfiguration: AuthProviderProps = {
    ...oidcConfigurationBase,
    client_id: "tiny-auth-frontend",
    onSigninCallback: (_user: User | void): void => {
        console.log("tiny-auth-frontend onSigninCallback")
        window.history.replaceState(
            {},
            document.title,
            window.location.pathname
        )
    },
    onRemoveUser: () => {
        console.log("tiny-auth-frontend onRemoveUser")
    },
}

console.log("tiny-auth authority is " + oidcConfiguration.authority)

const router = createBrowserRouter([
    {
        path: "/",
        element: <Root />,
        children: [
            {
                path: "oidc-login-redirect",
                element: <Root />,
            },
        ],
    },
]);

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
    <React.StrictMode>
        <RouterProvider router={router}/>
    </React.StrictMode>,
)

function Root() {
    return (
        <AuthProvider {...oidcConfiguration}>
            <App/>
        </AuthProvider>
    );
}

function resolveAuthority() {
    let auth = document.getElementById("tiny-auth-provider")?.getAttribute("href");
    if (auth === null || auth === undefined)
        auth = "";

    const oidcAuthority: string = auth;
    return oidcAuthority;
}