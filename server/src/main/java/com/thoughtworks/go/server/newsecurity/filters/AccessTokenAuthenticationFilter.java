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

package com.thoughtworks.go.server.newsecurity.filters;

import com.thoughtworks.go.domain.User;
import com.thoughtworks.go.server.domain.accesstoken.AccessToken;
import com.thoughtworks.go.server.newsecurity.handlers.BasicAuthenticationWithChallengeFailureResponseHandler;
import com.thoughtworks.go.server.newsecurity.models.AuthenticationToken;
import com.thoughtworks.go.server.newsecurity.models.Credentials;
import com.thoughtworks.go.server.newsecurity.utils.SessionUtils;
import com.thoughtworks.go.server.security.AuthorityGranter;
import com.thoughtworks.go.server.security.userdetail.GoUserPrinciple;
import com.thoughtworks.go.server.service.AccessTokenService;
import com.thoughtworks.go.server.service.SecurityService;
import com.thoughtworks.go.server.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;

@Component
public class AccessTokenAuthenticationFilter extends OncePerRequestFilter {
    protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

    private static final Pattern BEARER_AUTH_EXTRACTOR_PATTERN = Pattern.compile("bearer (.*)", Pattern.CASE_INSENSITIVE);

    protected final SecurityService securityService;
    private AccessTokenService accessTokenService;
    private UserService userService;
    private BasicAuthenticationWithChallengeFailureResponseHandler responseHandler;
    private final AuthorityGranter authorityGranter;


    @Autowired
    public AccessTokenAuthenticationFilter(SecurityService securityService, AccessTokenService accessTokenService, UserService userService, BasicAuthenticationWithChallengeFailureResponseHandler responseHandler, AuthorityGranter authorityGranter) {
        this.securityService = securityService;
        this.accessTokenService = accessTokenService;
        this.userService = userService;
        this.responseHandler = responseHandler;
        this.authorityGranter = authorityGranter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
        try {
            if (!securityService.isSecurityEnabled()) {
                filterChain.doFilter(request, response);
                return;
            }


            final AccessTokenCredential tokenCredential = extractBasicAuthenticationCredentials(request.getHeader("Authorization"));

            LOGGER.debug("Security is enabled.");

            filterWhenSecurityEnabled(request, response, filterChain, tokenCredential);

        } catch (AuthenticationException e) {
            onAuthenticationFailure(request, response, e.getMessage());
        }
    }


    private AccessTokenCredential extractBasicAuthenticationCredentials(String authorizationHeader) {
        if (isBlank(authorizationHeader)) {
            return null;
        }

        final Matcher matcher = BEARER_AUTH_EXTRACTOR_PATTERN.matcher(authorizationHeader);
        if (matcher.matches()) {
            final String token = matcher.group(1);

            return new AccessTokenCredential(token);
        }

        return null;
    }

    public class AccessTokenCredential implements Credentials {
        private String token;

        public AccessTokenCredential(String token) {
            this.token = token;
        }

        public String getToken() {
            return token;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            AccessTokenCredential that = (AccessTokenCredential) o;

            return token != null ? token.equals(that.token) : that.token == null;
        }

        @Override
        public int hashCode() {
            return token != null ? token.hashCode() : 0;
        }
    }


    private void filterWhenSecurityEnabled(HttpServletRequest request,
                                           HttpServletResponse response,
                                           FilterChain filterChain,
                                           AccessTokenCredential accessTokenCredential) throws IOException, ServletException {
        if (accessTokenCredential == null) {
            LOGGER.debug("Token auth credentials are not provided in request.");
            filterChain.doFilter(request, response);
        } else {
            try {
                Optional<AccessToken> optionalToken = accessTokenService.findTokenByValue(accessTokenCredential.getToken());

                if (!optionalToken.isPresent()) {
                    LOGGER.debug("Specified token was invalid.");
                    filterChain.doFilter(request, response);
                    return;
                }


                AccessToken accessToken = optionalToken.get();
                if (accessToken.getExpiresAt() < System.currentTimeMillis()) {
                    LOGGER.info("Specified token is expired");
                    onAuthenticationFailure(request, response, "Specified token is expired");
                    return;
                }

                User user = userService.load(accessToken.getUserId());
                if (!user.isEnabled()) {
                    LOGGER.info("User account associated with the token is disabled by admin");
                    onAuthenticationFailure(request, response, "User for the token is disabled by admin");
                    return;
                }

                final GoUserPrinciple goUserPrinciple = new GoUserPrinciple(user.getName(), user.getDisplayName(), authorityGranter.authorities(user.getName()));

                AuthenticationToken<AccessTokenCredential> authenticationToken = new AuthenticationToken<AccessTokenCredential>(goUserPrinciple, accessTokenCredential, null, System.currentTimeMillis(), null);

                SessionUtils.setAuthenticationTokenAfterRecreatingSession(authenticationToken, request);
                filterChain.doFilter(request, response);
            } catch (AuthenticationException e) {
                LOGGER.debug("Failed to authenticate user.", e);
                onAuthenticationFailure(request, response, e.getMessage());
            }
        }
    }

    private void onAuthenticationFailure(HttpServletRequest request,
                                           HttpServletResponse response,
                                           String errorMessage) throws IOException {
        responseHandler.handle(request, response, SC_UNAUTHORIZED, errorMessage);
    }
}
