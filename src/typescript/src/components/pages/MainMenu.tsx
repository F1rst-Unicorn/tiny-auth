import { Box } from "@mui/material";
import { Outlet } from "react-router-dom";
import TopAppBar from "../TopAppBar.tsx";
import { grey } from "@mui/material/colors";

export default function MainMenu() {
  return (
    <Box
      sx={{
        height: "100%",
        minHeight: "100%",
        flexGrow: 1,
        backgroundColor: grey["100"],
      }}
    >
      <TopAppBar />
      <Outlet />
    </Box>
  );
}
