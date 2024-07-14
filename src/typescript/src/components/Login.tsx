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

