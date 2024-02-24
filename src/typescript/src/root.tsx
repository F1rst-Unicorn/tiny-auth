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
