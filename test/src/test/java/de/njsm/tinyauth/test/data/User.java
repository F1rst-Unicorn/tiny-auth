/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package de.njsm.tinyauth.test.data;

public class User {

    private final String username;

    private final String password;

    private final String name;

    private final String familyName;

    private final String givenName;

    private final String middleName;

    private final String nickname;

    private final String preferredUsername;

    private final String profile;

    private final String picture;

    private final String website;

    private final String gender;

    private final String birthday;

    private final String zoneinfo;

    private final String locale;

    private final int updatedAt;

    private final String email;

    private final String address;

    private final String phone;

    public User(String username, String password, String name, String familyName, String givenName, String middleName, String nickname, String preferredUsername, String profile, String picture, String website, String gender, String birthday, String zoneinfo, String locale, int updatedAt, String email, String address, String phone) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.familyName = familyName;
        this.givenName = givenName;
        this.middleName = middleName;
        this.nickname = nickname;
        this.preferredUsername = preferredUsername;
        this.profile = profile;
        this.picture = picture;
        this.website = website;
        this.gender = gender;
        this.birthday = birthday;
        this.zoneinfo = zoneinfo;
        this.locale = locale;
        this.updatedAt = updatedAt;
        this.email = email;
        this.address = address;
        this.phone = phone;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getName() {
        return name;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getMiddleName() {
        return middleName;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public String getProfile() {
        return profile;
    }

    public String getPicture() {
        return picture;
    }

    public String getWebsite() {
        return website;
    }

    public String getGender() {
        return gender;
    }

    public String getBirthday() {
        return birthday;
    }

    public String getZoneinfo() {
        return zoneinfo;
    }

    public String getLocale() {
        return locale;
    }

    public int getUpdatedAt() {
        return updatedAt;
    }

    public String getEmail() {
        return email;
    }

    public String getAddress() {
        return address;
    }

    public String getPhone() {
        return phone;
    }
}
