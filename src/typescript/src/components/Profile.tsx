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

import {
  Box,
  Grid,
  TextField,
  Typography,
  Button,
  Card,
  Alert,
  CircularProgress,
} from "@mui/material";
import { useAuth } from "react-oidc-context";
import { useFetcher } from "react-router-dom";
import { useState } from "react";
import {
  HashedPasswordPbkdf2HmacSha256,
  ManagedPassword, SuccessfullyStoredPassword
} from "../core/changePassword.ts";
import { CURRENT, NEW } from "./actions/changePassword.ts";
import { buildUserName } from "../core/auth.ts";

export default function Profile() {
  const auth = useAuth();
  const [newPassword, setNewPassword] = useState("");
  const [newRepeatedPassword, setNewRepeatedPassword] = useState("");
  const fetcher = useFetcher();
  const actionData = fetcher.data as
    | undefined
    | HashedPasswordPbkdf2HmacSha256
    | ManagedPassword
    | SuccessfullyStoredPassword
    | Error;

  let resultAlert;
  if (actionData === undefined) {
    resultAlert = null;
  } else if (actionData instanceof HashedPasswordPbkdf2HmacSha256) {
    resultAlert = renderSuccessfulPasswordChange(actionData);
  } else if (actionData instanceof ManagedPassword) {
    resultAlert = renderSuccessfulManagedPasswordChange();
  } else if (actionData instanceof SuccessfullyStoredPassword) {
    resultAlert = renderSuccessfullyStoredPasswordChange();
  } else if (actionData) {
    resultAlert = (
      <Alert
        severity="error"
        sx={{
          marginBottom: 4,
        }}
      >
        {actionData.message}
      </Alert>
    );
  }

  let submitButton;
  if (fetcher.state === "submitting") {
    submitButton = (
      <>
        <Button variant="contained" type="submit" disabled={true}>
          Save{" "}
        </Button>
        <CircularProgress size={20} sx={{ marginLeft: 2 }} />
      </>
    );
  } else {
    submitButton = (
      <Button variant="contained" type="submit">
        Save
      </Button>
    );
  }

  return (
    <Box p={2}>
      <Typography variant={"h4"} component={"h1"}>
        {buildUserName(auth.user)}
      </Typography>
      <Card sx={{ padding: 2 }}>
        <Typography
          variant={"h6"}
          component={"h2"}
          sx={{
            paddingBottom: 2,
          }}
        >
          Change Password
        </Typography>
        {resultAlert}
        <fetcher.Form method="post" action="../api/changePassword">
          <Grid container spacing={2} direction="column">
            <Grid item>
              <TextField
                required
                name={CURRENT}
                label="Current Password"
                type="password"
                autoComplete="current-password"
              />
            </Grid>
            <Grid item>
              <TextField
                required
                name={NEW}
                label="New Password"
                type="password"
                onChange={(event) => {
                  setNewPassword(event.target.value);
                }}
              />
            </Grid>
            <Grid item>
              <TextField
                error={newPassword !== newRepeatedPassword}
                required
                id="newRepeated"
                label="Repeat New Password"
                type="password"
                onChange={(event) => {
                  setNewRepeatedPassword(event.target.value);
                }}
                helperText={
                  newPassword !== newRepeatedPassword
                    ? "New Passwords differ"
                    : null
                }
                sx={{
                  paddingBottom: 2,
                }}
              />
            </Grid>
            <Grid item>{submitButton}</Grid>
          </Grid>
        </fetcher.Form>
      </Card>
    </Box>
  );
}

function renderSuccessfulPasswordChange(data: HashedPasswordPbkdf2HmacSha256) {
  return (
    <Alert
      severity="success"
      sx={{
        marginBottom: 4,
      }}
    >
      This server doesn't support storing the password automatically. Send this
      text to your administrator:
      <br />
      <Typography sx={{ fontFamily: "monospace" }}>
        password:
        <br />
        &nbsp;&nbsp;Pbkdf2HmacSha256:
        <br />
        &nbsp;&nbsp;&nbsp;&nbsp;credential: {data.credential}
        <br />
        &nbsp;&nbsp;&nbsp;&nbsp;iterations: {data.iterations}
        <br />
        &nbsp;&nbsp;&nbsp;&nbsp;salt: {data.salt}
        <br />
      </Typography>
    </Alert>
  );
}

function renderSuccessfulManagedPasswordChange() {
  return (
    <Alert
      severity="info"
      sx={{
        marginBottom: 4,
      }}
    >
      Your password is not stored in tiny-auth and thus cannot be changed here.
    </Alert>
  );
}

function renderSuccessfullyStoredPasswordChange() {
  return (
    <Alert
      severity="success"
      sx={{
        marginBottom: 4,
      }}
    >
      Your new password was stored.
    </Alert>
  );
}
