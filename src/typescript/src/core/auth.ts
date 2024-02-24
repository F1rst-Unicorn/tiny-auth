import { User } from "oidc-client-ts";

export interface UserStore {
  getUser(): User | null;
}

export function buildUserName(user: User | null | undefined) {
  let username = "";
  if (user?.profile?.given_name !== undefined) {
    username = user?.profile?.given_name;
    if (user?.profile?.family_name !== undefined) {
      username = username + " " + user?.profile?.family_name;
    }
  } else if (user?.profile?.sub !== undefined) {
    username = user?.profile?.sub;
  }
  return username;
}
