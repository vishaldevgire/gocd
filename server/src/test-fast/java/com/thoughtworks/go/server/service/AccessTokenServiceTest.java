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

package com.thoughtworks.go.server.service;

import com.thoughtworks.go.config.exceptions.RecordNotFoundException;
import com.thoughtworks.go.server.dao.AccessTokenDao;
import com.thoughtworks.go.server.domain.accesstoken.AccessToken;
import com.thoughtworks.go.server.domain.accesstoken.AccessTokenInfo;
import com.thoughtworks.go.util.TestingClock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

class AccessTokenServiceTest {
    private AccessTokenService accessTokenService;
    private TestingClock testingClock;
    @Mock
    private AccessTokenDao accessTokenDao;

    @BeforeEach
    void setUp() {
        initMocks(this);

        testingClock = new TestingClock();
        accessTokenService = new AccessTokenService(accessTokenDao);
    }

    @AfterEach
    void tearDown() {

    }

    @Nested
    class CreateToken {

        @Test
        void shouldGenerateToken() {
            final AccessTokenInfo accessTokenInfo = new AccessTokenInfo("PersonalAccessToken", "This is a dummy token", testingClock.currentTimeMillis());

            final ArgumentCaptor<AccessToken> accessTokenArgumentCaptor = ArgumentCaptor.forClass(AccessToken.class);

            final String token = accessTokenService.createToken(1L, accessTokenInfo);
            assertThat(token).isNotNull().hasSize(32);

            verify(accessTokenDao).save(accessTokenArgumentCaptor.capture());

            final AccessToken captorValue = accessTokenArgumentCaptor.getValue();

            assertThat(token).isEqualTo(captorValue.getValue());
            assertThat(captorValue.getName()).isEqualTo("PersonalAccessToken");
            assertThat(captorValue.getDescription()).isEqualTo("This is a dummy token");
            assertThat(captorValue.getExpiresAt()).isEqualTo(testingClock.currentTimeMillis());
            assertThat(captorValue.getUserId()).isEqualTo(1L);

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }

        @Test
        void shouldErrorOutIfTokenWithGivenNameAlreadyExist() {
            final AccessToken existingToken = new AccessToken("PersonalAccessToken", "This is previously created token.", testingClock.currentTimeMillis());
            final AccessTokenInfo accessTokenInfo = new AccessTokenInfo("PersonalAccessToken", "This is a dummy token", testingClock.currentTimeMillis());

            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(singletonList(existingToken));

            final Exception exception = assertThrows(Exception.class, () -> accessTokenService.createToken(1L, accessTokenInfo));

            assertThat(exception.getMessage()).isEqualTo("Token with name 'PersonalAccessToken' already exist.");

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }
    }

    @Nested
    class GetAllTokensForUser {
        @Test
        void shouldGetAllTokens() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Arrays.asList(
                    new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                    new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
            ));

            final List<AccessToken> allTokensForUser = accessTokenService.listAllTokensForUser(1L);

            assertThat(allTokensForUser)
                    .hasSize(2)
                    .contains(
                            new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                            new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
                    );

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }

        @Test
        void shouldReturnEmptyListIfNoTokensFoundForGivenUSerId() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Collections.emptyList());

            final List<AccessToken> allTokensForUser = accessTokenService.listAllTokensForUser(1L);

            assertThat(allTokensForUser).isEmpty();

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }
    }

    @Nested
    class GetTokenForUser {

        @Test
        void shouldGetToken() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Arrays.asList(
                    new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                    new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
            ));

            final Optional<AccessToken> optionalAccessToken = accessTokenService.findTokenForUser(1L, "Token-B");

            assertThat(optionalAccessToken.isPresent()).isTrue();
            assertThat(optionalAccessToken.get())
                    .isEqualTo(new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis()));

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }

        @Test
        void shouldReturnEmptyOptionWhenTokenDoesNotExist() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Arrays.asList(
                    new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                    new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
            ));

            final Optional<AccessToken> optionalAccessToken = accessTokenService.findTokenForUser(1L, "Token-C");

            assertThat(optionalAccessToken.isPresent()).isFalse();

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }
    }

    @Nested
    class DeleteToken {
        @Test
        void shouldDeleteToken() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Arrays.asList(
                    new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                    new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
            ));

            accessTokenService.deleteToken(1L, "Token-B");

            verify(accessTokenDao).listAllTokensForUser(1L);
            verify(accessTokenDao).delete(new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis()));
            verifyNoMoreInteractions(accessTokenDao);
        }

        @Test
        void shouldThrowRecordNotFoundExceptionWhenTokenDoesNotExist() {
            when(accessTokenDao.listAllTokensForUser(1L)).thenReturn(Arrays.asList(
                    new AccessToken("Token-A", "token for a", testingClock.currentTimeMillis()),
                    new AccessToken("Token-B", "token for b", testingClock.currentTimeMillis())
            ));

            final RecordNotFoundException thrown = assertThrows(RecordNotFoundException.class, () -> accessTokenService.deleteToken(1L, "Token-C"));

            assertThat(thrown.getMessage()).isEqualTo("The token with name 'Token-C' was not found.");

            verify(accessTokenDao).listAllTokensForUser(1L);
            verifyNoMoreInteractions(accessTokenDao);
        }
    }
}
