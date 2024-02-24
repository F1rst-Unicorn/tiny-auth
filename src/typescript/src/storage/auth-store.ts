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
