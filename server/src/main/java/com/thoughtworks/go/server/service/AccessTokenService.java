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
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Service
public class AccessTokenService {
    private AccessTokenDao accessTokenDao;

    @Autowired
    public AccessTokenService(AccessTokenDao accessTokenDao) {
        this.accessTokenDao = accessTokenDao;
    }

    public String createToken(Long userId, AccessTokenInfo accessTokenInfo) {
        final Optional<AccessToken> tokenFromDB = findTokenForUser(userId, accessTokenInfo.getName());

        if (tokenFromDB.isPresent()) {
            throw new RuntimeException(format("Token with name '%s' already exist.", accessTokenInfo.getName()));
        }

        final AccessToken accessToken = AccessToken.from(userId, accessTokenInfo);
        return accessTokenDao.save(accessToken).getValue();
    }

    public List<AccessToken> listAllTokensForUser(Long userId) {
        return accessTokenDao.listAllTokensForUser(userId);
    }

    public Optional<AccessToken> findTokenForUser(Long userId, String tokenName) {
        return listAllTokensForUser(userId)
                .stream()
                .filter(accessToken -> StringUtils.equals(accessToken.getName(), tokenName))
                .findFirst();
    }

    public void deleteToken(Long userId, String tokenName) {
        final Optional<AccessToken> tokenFromDB = findTokenForUser(userId, tokenName);

        if (!tokenFromDB.isPresent()) {
            throw new RecordNotFoundException(format("The token with name '%s' was not found.", tokenName));
        }

        accessTokenDao.delete(tokenFromDB.get());
    }
}
