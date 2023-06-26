import React from "react";
import {useAuth} from "react-oidc-context";

function App() {
    const auth = useAuth();

    React.useEffect(() => {
        return auth.events.addUserLoaded(() => {
            console.log("tiny-auth-frontend user loaded")
        });
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addSilentRenewError(() => {
            console.log("tiny-auth-frontend silentRenewError")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addUserSessionChanged(() => {
            console.log("tiny-auth-frontend UserSessionChanged")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addUserUnloaded(() => {
            console.log("tiny-auth-frontend UserUnloaded")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addUserSignedIn(() => {
            console.log("tiny-auth-frontend UserSignedIn")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addUserSignedOut(() => {
            console.log("tiny-auth-frontend UserSignedOut")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addAccessTokenExpired(() => {
            console.log("tiny-auth-frontend AccessTokenExpired")
        })
    }, [auth.events]);
    React.useEffect(() => {
        return auth.events.addAccessTokenExpiring(() => {
            console.log("tiny-auth-frontend AccessTokenExpiring")
        })
    }, [auth.events]);

    switch (auth.activeNavigator) {
        case "signinSilent":
            return <div>Signing you in...</div>;
        case "signoutRedirect":
            return <div>Signing you out...</div>;
    }

    if (auth.isLoading) {
        return <div>Loading...</div>;
    }

    if (auth.error) {
        return <div>
            Oops... {auth.error.message}
            <button onClick={() => void auth.removeUser()}>Log out</button>
        </div>;
    }

    if (auth.isAuthenticated) {
        return (
            <div>
                Hello {auth.user?.profile.sub}{" "}
                <button onClick={() => void auth.removeUser()}>Log out</button>
            </div>
        );
    }

    return <button onClick={() => void auth.signinRedirect()}>Log in</button>;
}

export default App
