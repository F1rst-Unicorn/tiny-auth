import { changePasswordInteractor } from "../constructor.ts";
import { ApiService } from "../api/api.ts";

export class Interactor {
  private readonly apiService: ApiService;

  constructor(apiService: ApiService) {
    this.apiService = apiService;
  }

  public async changePassword(
    data: ChangePasswordData,
  ): Promise<HashedPasswordPbkdf2HmacSha256> {
    return await this.apiService.changePassword(data);
  }
}

export async function changePassword(
  data: ChangePasswordData,
): Promise<HashedPasswordPbkdf2HmacSha256 | Error> {
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
