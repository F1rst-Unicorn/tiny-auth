import { AuthContextProps, useAuth } from "react-oidc-context";
import Button from "@mui/material/Button";
import {
  AppBar,
  IconButton,
  Menu,
  MenuItem,
  Toolbar,
  Typography,
} from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import { NavLink, redirect } from "react-router-dom";
import { AccountCircle } from "@mui/icons-material";
import React from "react";
import { webBase } from "../router.tsx";
import { buildUserName } from "../core/auth.ts";

async function logout(auth: AuthContextProps) {
  await auth.removeUser();
  return redirect(`/`);
}

export default function TopAppBar() {
  const auth = useAuth();
  const [profileMenuAnchor, setProfileMenuAnchor] =
    React.useState<null | HTMLElement>(null);
  const openProfileMenu = (event: React.MouseEvent<HTMLElement>) => {
    setProfileMenuAnchor(event.currentTarget);
  };
  const closeProfileMenu = () => {
    setProfileMenuAnchor(null);
  };
  return (
    <AppBar position="static">
      <Toolbar>
        <IconButton
          size="large"
          edge="start"
          color="inherit"
          aria-label="menu"
          sx={{ mr: 2 }}
        >
          <MenuIcon />
        </IconButton>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          <NavLink to={webBase}>tiny-auth</NavLink>
        </Typography>
        <Typography variant="h6" component="div" px={2}>
          {buildUserName(auth.user)}
        </Typography>
        <IconButton
          size="large"
          aria-label="profile of current user"
          aria-controls="menu-appbar"
          aria-haspopup="true"
          onClick={openProfileMenu}
          color="inherit"
        >
          <AccountCircle />
        </IconButton>
        <Menu
          id="menu-appbar"
          anchorEl={profileMenuAnchor}
          anchorOrigin={{
            vertical: "bottom",
            horizontal: "right",
          }}
          keepMounted
          transformOrigin={{
            vertical: "top",
            horizontal: "right",
          }}
          open={Boolean(profileMenuAnchor)}
          onClose={closeProfileMenu}
        >
          <MenuItem onClick={closeProfileMenu}>
            <NavLink to={"profile"}>My Profile</NavLink>
          </MenuItem>
        </Menu>
        <Button
          sx={{ mx: 2 }}
          color={"inherit"}
          onClick={() => void logout(auth)}
        >
          Log out
        </Button>
      </Toolbar>
    </AppBar>
  );
}
