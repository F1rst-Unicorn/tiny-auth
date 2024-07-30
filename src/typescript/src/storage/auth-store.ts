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
import { UserStore } from "../core/auth.ts";

export class UserStoreImpl implements UserStore {
  private readonly oidcAuthority: string;
  private readonly clientId: string;

  constructor(oidcAuthority: string, clientId: string) {
    this.oidcAuthority = oidcAuthority;
    this.clientId = clientId;
  }

  public getUser(): User | null {
    const oidcStorage = window.localStorage.getItem(
      `oidc.user:${this.oidcAuthority}:${this.clientId}`,
    );
    if (!oidcStorage) {
      return null;
    }

    return User.fromStorageString(oidcStorage);
  }
}
