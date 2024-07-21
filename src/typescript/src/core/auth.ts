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
