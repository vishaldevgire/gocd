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

package com.thoughtworks.go.domain;

import com.thoughtworks.go.server.domain.accesstoken.AccessToken;
import com.thoughtworks.go.server.domain.accesstoken.AccessTokenInfo;
import com.thoughtworks.go.server.exceptions.AccessTokenValidationException;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AccessTokenTest {

    @Nested
    class CreateFromAccessTokenInfo {
        @Test
        void shouldCreateAccessToken() {
            AccessTokenInfo accessTokenInfo = new AccessTokenInfo("token1", "A normal token", 11223344L);

            AccessToken accessToken = AccessToken.from(1L, accessTokenInfo);

            assertThat(accessToken.getUserId()).isEqualTo(1L);
            assertThat(accessToken.getName()).isEqualTo("token1");
            assertThat(accessToken.getDescription()).isEqualTo("A normal token");
            assertThat(accessToken.getExpiresAt()).isEqualTo(11223344L);
            assertThat(accessToken.getValue()).isNotNull();
        }
    }

    @Nested
    class Validate {
        @Test
        void shouldErrorOutIfNameIsLongerThan255Characters() {
            AccessToken accessToken = new AccessToken(longString(270), "A normal token", 11223344L);

            AccessTokenValidationException exception = assertThrows(AccessTokenValidationException.class, () -> accessToken.validate());

            assertThat(exception.getMessage()).isEqualTo("Token name must not exceed 255 characters.");
        }

        @Test
        void shouldErrorOutIfDescriptionIsLongerThan512Characters() {
            AccessToken accessToken = new AccessToken("Token1", longString(600), 11223344L);

            AccessTokenValidationException exception = assertThrows(AccessTokenValidationException.class, () -> accessToken.validate());

            assertThat(exception.getMessage()).isEqualTo("Token description must not exceed 512 characters.");
        }

        @Test
        void shouldErrorOutIfUserIdIsInvalid() {
            AccessToken accessToken = AccessToken.from(0L, new AccessTokenInfo("Token1", longString(600), 11223344L));

            AccessTokenValidationException exception = assertThrows(AccessTokenValidationException.class, () -> accessToken.validate());

            assertThat(exception.getMessage()).isEqualTo("Token description must not exceed 512 characters.");
        }
    }

    private String longString(int length) {
        return RandomStringUtils.random(length);
    }
}
