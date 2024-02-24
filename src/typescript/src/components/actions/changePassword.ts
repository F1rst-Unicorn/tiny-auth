import { ActionFunction } from "react-router-dom";
import {
  changePassword,
  ChangePasswordData,
} from "../../core/changePassword.ts";

export const CURRENT = "current";
export const NEW = "new";

export const changePasswordAction: ActionFunction = async ({ request }) => {
  const formData: FormData = await request.formData();
  const current = formData.get(CURRENT);
  if (current === null) {
    throw new Error("current password missing");
  }
  const newPassword = formData.get(NEW);
  if (newPassword === null) {
    throw new Error("new password missing");
  }
  try {
    return await changePassword(
      new ChangePasswordData(current.toString(), newPassword.toString()),
    );
  } catch (error) {
    return error;
  }
};
