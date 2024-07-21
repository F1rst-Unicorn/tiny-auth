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

import { AuthProvider } from "react-oidc-context";
import { GlobalStyles, ThemeProvider } from "@mui/material";
import { theme } from "./theme.tsx";
import App from "./App.tsx";
import { styles } from "./styles.ts";
import { oidcConfiguration } from "./constructor.ts";

export default function Root() {
  return (
    <AuthProvider {...oidcConfiguration}>
      <GlobalStyles styles={styles} />
      <ThemeProvider theme={theme}>
        <App />
      </ThemeProvider>
    </AuthProvider>
  );
}
