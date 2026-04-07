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
import { Box, Stack, Typography } from "@mui/material";
import favicon from "../assets/favicon.svg";

export default function Login(props: {
  errorMessage: string;
  infoMessage: string;
}) {
  const auth = useAuth();

  return (
    <Stack
      spacing={2}
      direction={"column"}
      sx={{
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <Box>
        <Box height={250} component="img" src={favicon} alt="tiny-auth Logo" />
      </Box>
      <Box>
        <Button
          variant="contained"
          onClick={() =>
            void auth.signinRedirect({
              nonce: getNonce(),
            })
          }
        >
          Log in to tiny-auth
        </Button>
      </Box>
      <Box>
        <Typography color="error">{props.errorMessage}</Typography>
      </Box>
      <Box>
        <Typography>{props.infoMessage}</Typography>
      </Box>
    </Stack>
  );
}

function getNonce() {
  return (
    getRandomValue() +
    getRandomValue() +
    getRandomValue() +
    getRandomValue() +
    getRandomValue() +
    getRandomValue() +
    getRandomValue() +
    getRandomValue()
  );
}

function getRandomValue() {
  return Math.floor(Math.random() * 999).toString();
}
