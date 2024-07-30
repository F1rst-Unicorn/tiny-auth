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
