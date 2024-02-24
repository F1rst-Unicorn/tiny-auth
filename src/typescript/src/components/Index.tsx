import { Box, Grid } from "@mui/material";
import favicon from "../assets/favicon.svg";

export default function Index() {
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
    </Grid>
  );
}
