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

import com.thoughtworks.go.domain.User;
import com.thoughtworks.go.server.domain.accesstoken.AccessToken;
import com.thoughtworks.go.server.transaction.TransactionTemplate;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.slf4j.Logger;
import org.springframework.orm.hibernate3.support.HibernateDaoSupport;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;

import java.util.List;

@Component
public class AccessTokenDao extends HibernateDaoSupport {
    private static final Logger LOGGER = org.slf4j.LoggerFactory.getLogger(AccessTokenDao.class);
    private final SessionFactory sessionFactory;
    private final TransactionTemplate transactionTemplate;

    public AccessTokenDao(SessionFactory sessionFactory, TransactionTemplate transactionTemplate) {
        this.sessionFactory = sessionFactory;
        this.transactionTemplate = transactionTemplate;
        setSessionFactory(sessionFactory);
    }

    public void save(AccessToken accessToken) {
        transactionTemplate.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                sessionFactory.getCurrentSession().save(accessToken);
            }
        });
    }

    public List<AccessToken> listAllTokensForUser(Long userId) {
        return transactionTemplate.execute((TransactionCallback<List<AccessToken>>) status -> sessionFactory
                .getCurrentSession()
                .createCriteria(AccessToken.class)
                .add(Restrictions.eq("user", User.getUserInstanceWithId(userId)))
                .setCacheable(true)
                .list());
    }

    public void delete(AccessToken accessToken) {
        transactionTemplate.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                sessionFactory.getCurrentSession().delete(accessToken);
            }
        });
    }
}
