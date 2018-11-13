/*
 * Copyright 2018 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thoughtworks.go.server.domain.accesstoken;

import com.thoughtworks.go.domain.PersistentObject;
import com.thoughtworks.go.domain.User;
import com.thoughtworks.go.server.exceptions.AccessTokenValidationException;
import org.apache.commons.lang3.StringUtils;

import java.util.UUID;

public class AccessToken extends PersistentObject {
    private String name;
    private String description;
    private String value;
    private Long expiresAt;
    private User user;

    private AccessToken() {
    }

    public AccessToken(String name, String description, Long expiresAt) {
        this.name = name;
        this.description = description;
        this.expiresAt = expiresAt;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getValue() {
        return value;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }

    public Long getUserId() {
        return user.getId();
    }

    public static AccessToken from(Long userId, AccessTokenInfo accessTokenInfo) {
        final AccessToken accessToken = new AccessToken(accessTokenInfo.getName(), accessTokenInfo.getDescription(), accessTokenInfo.getExpiresAt());
        accessToken.value = UUID.randomUUID().toString().replaceAll("-", "").toUpperCase();

        accessToken.user = User.getUserInstanceWithId(userId);
        return accessToken;
    }

    public void validate() {
        if (StringUtils.length(getName()) > 255) {
            AccessTokenValidationException.throwBecauseInvalidName();
        }

        if (StringUtils.length(getDescription()) > 512) {
            AccessTokenValidationException.throwBecauseInvalidDescription();
        }

        if (getUserId() == null || getUserId() <= 0) {
            AccessTokenValidationException.throwBecauseInvalidUserId(getUserId());
        }
    }
}
