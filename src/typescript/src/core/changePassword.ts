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

import { changePasswordInteractor } from "../constructor.ts";
import { ApiService } from "../api/api.ts";

export class Interactor {
  private readonly apiService: ApiService;

  constructor(apiService: ApiService) {
    this.apiService = apiService;
  }

  public async changePassword(
    data: ChangePasswordData,
  ): Promise<ChangePasswordResult> {
    return await this.apiService.changePassword(data);
  }
}

export async function changePassword(
  data: ChangePasswordData,
): Promise<ChangePasswordResult | Error> {
  return changePasswordInteractor.changePassword(data);
}

export class ChangePasswordData {
  private readonly _currentPassword: string;

  private readonly _newPassword: string;

  constructor(currentPassword: string, newPassword: string) {
    this._currentPassword = currentPassword;
    this._newPassword = newPassword;
  }

  get currentPassword(): string {
    return this._currentPassword;
  }

  get newPassword(): string {
    return this._newPassword;
  }
}

export class ChangePasswordResult {}

export class ManagedPassword {}

export class SuccessfullyStoredPassword {}

export class HashedPasswordPbkdf2HmacSha256 extends ChangePasswordResult {
  private readonly _credential: string;
  private readonly _iterations: number;
  private readonly _salt: string;

  constructor(credential: string, iterations: number, salt: string) {
    super();
    this._credential = credential;
    this._iterations = iterations;
    this._salt = salt;
  }

  get credential(): string {
    return this._credential;
  }

  get iterations(): number {
    return this._iterations;
  }

  get salt(): string {
    return this._salt;
  }
}
