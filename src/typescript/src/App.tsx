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

import React from "react";
import { useAuth } from "react-oidc-context";
import Login from "./components/Login.tsx";
import MainMenu from "./components/pages/MainMenu.tsx";
import { CircularProgress, Grid } from "@mui/material";

export default function App() {
  const auth = useAuth();

  React.useEffect(() => {
    return auth.events.addUserLoaded(() => {
      console.log("tiny-auth-frontend user loaded");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addSilentRenewError((error) => {
      console.log("tiny-auth-frontend silentRenewError " + error.message);
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addUserSessionChanged(() => {
      console.log("tiny-auth-frontend UserSessionChanged");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addUserUnloaded(() => {
      console.log("tiny-auth-frontend UserUnloaded");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addUserSignedIn(() => {
      console.log("tiny-auth-frontend UserSignedIn");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addUserSignedOut(() => {
      console.log("tiny-auth-frontend UserSignedOut");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addAccessTokenExpired(() => {
      console.log("tiny-auth-frontend AccessTokenExpired");
    });
  }, [auth.events]);
  React.useEffect(() => {
    return auth.events.addAccessTokenExpiring(() => {
      console.log("tiny-auth-frontend AccessTokenExpiring");
    });
  }, [auth.events]);

  if (auth.isAuthenticated) {
    return <MainMenu />;
  }

  switch (auth.activeNavigator) {
    case "signinSilent":
      return <Login errorMessage={""} infoMessage={"Signing you in..."} />;
    case "signoutRedirect":
      return <Login errorMessage={""} infoMessage={"Signing you out..."} />;
  }

  if (auth.isLoading) {
    return (
      <Grid
        container
        spacing={2}
        direction={"column"}
        justifyContent={"center"}
        alignItems={"center"}
      >
        <Grid item>
          <CircularProgress size={75} sx={{ padding: 5 }} />
        </Grid>
      </Grid>
    );
  }

  if (auth.error) {
    return <Login errorMessage={auth.error.message} infoMessage={""} />;
  }

  return <Login errorMessage={""} infoMessage={""} />;
}
