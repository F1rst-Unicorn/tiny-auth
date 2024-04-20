import {
  ChangePasswordData,
  ChangePasswordResult,
  HashedPasswordPbkdf2HmacSha256,
  ManagedPassword,
} from "../core/changePassword.ts";
import { TinyAuthApiClient } from "../generated/tiny-auth/tiny-auth.client.ts";
import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport";
import { UserStore } from "../core/auth.ts";
import { RpcOptions, RpcError } from "@protobuf-ts/runtime-rpc";
import {
  GENERAL_ERROR,
  NO_ID_TOKEN,
  UNKNOWN_PASSWORD_TYPE,
  WRONG_PASSWORD,
} from "../core/error.ts";

export class ApiService {
  private service: TinyAuthApiClient;
  private userStore: UserStore;

  constructor(url: string, userStore: UserStore) {
    const transport = new GrpcWebFetchTransport({
      format: "binary",
      baseUrl: url,
    });
    this.service = new TinyAuthApiClient(transport);
    this.userStore = userStore;
  }

  async changePassword(
    data: ChangePasswordData,
  ): Promise<ChangePasswordResult> {
    try {
      const response = await this.service.changePassword(
        {
          currentPassword: data.currentPassword,
          newPassword: data.newPassword,
        },
        this.buildOptions(),
      );
      if (response.response.hashedPassword.oneofKind === "pbkdf2HmacSha256") {
        return new HashedPasswordPbkdf2HmacSha256(
          response.response.hashedPassword.pbkdf2HmacSha256.credential,
          response.response.hashedPassword.pbkdf2HmacSha256.iterations,
          response.response.hashedPassword.pbkdf2HmacSha256.salt,
        );
      } else if (response.response.hashedPassword.oneofKind === "managed") {
        return new ManagedPassword();
      } else {
        throw new Error(UNKNOWN_PASSWORD_TYPE);
      }
    } catch (error) {
      if (error instanceof RpcError) {
        switch (error.code) {
          case "PERMISSION_DENIED":
            throw new Error(WRONG_PASSWORD);
          case "UNAUTHENTICATED":
            throw new Error(NO_ID_TOKEN);
          default:
            throw new Error(GENERAL_ERROR);
        }
      } else {
        throw error;
      }
    }
  }

  private buildOptions(): RpcOptions {
    return {
      meta: {
        "x-authorization": "Bearer " + this.accessToken(),
      },
    };
  }

  private accessToken(): string {
    const accessToken = this.userStore.getUser()?.access_token;
    if (accessToken === undefined) {
      throw new Error("no access token");
    } else {
      return accessToken;
    }
  }
}
