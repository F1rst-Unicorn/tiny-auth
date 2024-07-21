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

import { useAuth } from "react-oidc-context";
import Button from "@mui/material/Button";
import { Box, Grid, Typography } from "@mui/material";
import favicon from "../assets/favicon.svg";

export default function Login(props: {
  errorMessage: string;
  infoMessage: string;
}) {
  const auth = useAuth();

  return (
    <Grid
      container
      spacing={2}
      direction={"column"}
      justifyContent={"center"}
      alignItems={"center"}
    >
      <Grid item>
        <Box height={250} component="img" src={favicon} alt="tiny-auth Logo" />
      </Grid>
      <Grid item>
        <Button variant="contained" onClick={() => void auth.signinRedirect({
          nonce: getNonce()
        })}>
          Log in to tiny-auth
        </Button>
      </Grid>
      <Grid item>
        <Typography color="error">{props.errorMessage}</Typography>
      </Grid>
      <Grid item>
        <Typography>{props.infoMessage}</Typography>
      </Grid>
    </Grid>
  );
}

function getNonce() {
  return getRandomValue()
    + getRandomValue()
    + getRandomValue()
    + getRandomValue()
    + getRandomValue()
    + getRandomValue()
    + getRandomValue()
    + getRandomValue();
}

function getRandomValue() {
  return Math.floor(Math.random() * 999).toString();
}

