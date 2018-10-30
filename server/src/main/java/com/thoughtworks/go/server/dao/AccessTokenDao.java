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

package com.thoughtworks.go.server.dao;

import com.thoughtworks.go.server.domain.accesstoken.AccessToken;
import com.thoughtworks.go.server.transaction.TransactionTemplate;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.orm.hibernate3.support.HibernateDaoSupport;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionCallback;

import java.util.List;

@Component
public class AccessTokenDao extends HibernateDaoSupport {
    private final SessionFactory sessionFactory;
    private final TransactionTemplate transactionTemplate;

    public AccessTokenDao(SessionFactory sessionFactory, TransactionTemplate transactionTemplate) {
        this.sessionFactory = sessionFactory;
        this.transactionTemplate = transactionTemplate;
        setSessionFactory(sessionFactory);
    }

    public AccessToken save(AccessToken accessToken) {
        assertUserId(accessToken.getUserId());
        return transactionTemplate.execute(status -> (AccessToken) sessionFactory.getCurrentSession().save(accessToken));
    }

    public List<AccessToken> listAllTokensForUser(Long userId) {
        return transactionTemplate.execute((TransactionCallback<List<AccessToken>>) status -> sessionFactory
                .getCurrentSession()
                .createCriteria(AccessToken.class)
                .add(Restrictions.eq("userId", userId))
                .setCacheable(true)
                .list());
    }

    public void delete(AccessToken accessToken) {
        transactionTemplate.execute((TransactionCallback<Void>) status -> {
            sessionFactory.getCurrentSession().delete(accessToken);
            return null;
        });
    }

    private void assertUserId(Long userId) {
        if (userId == null || userId <= 0) {
            throw new IllegalArgumentException(String.format("UserId with value '%s' is not permitted. Access Token must be associated with a valid user-id", userId));
        }
    }
}
