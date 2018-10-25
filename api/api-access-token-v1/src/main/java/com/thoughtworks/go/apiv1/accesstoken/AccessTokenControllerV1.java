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

package com.thoughtworks.go.apiv1.accesstoken;

import com.fasterxml.jackson.databind.JsonNode;
import com.thoughtworks.go.api.ApiController;
import com.thoughtworks.go.api.ApiVersion;
import com.thoughtworks.go.api.CrudController;
import com.thoughtworks.go.api.representers.JsonReader;
import com.thoughtworks.go.api.spring.ApiAuthenticationHelper;
import com.thoughtworks.go.api.util.GsonTransformer;
import com.thoughtworks.go.api.util.HaltApiResponses;
import com.thoughtworks.go.apiv1.accesstoken.representers.AccessTokenRepresenter;
import com.thoughtworks.go.apiv1.accesstoken.representers.AccessTokensRepresenter;
import com.thoughtworks.go.config.exceptions.RecordNotFoundException;
import com.thoughtworks.go.domain.AccessToken;
import com.thoughtworks.go.i18n.LocalizedMessage;
import com.thoughtworks.go.server.service.AccessTokenService;
import com.thoughtworks.go.server.service.EntityHashingService;
import com.thoughtworks.go.server.service.result.HttpLocalizedOperationResult;
import com.thoughtworks.go.spark.Routes.AccessTokenAPI;
import com.thoughtworks.go.spark.spring.SparkSpringController;
import com.thoughtworks.go.util.Clock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import spark.Request;
import spark.Response;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.eclipse.jgit.util.HttpSupport.TEXT_PLAIN;
import static spark.Spark.*;

@Component
public class AccessTokenControllerV1 extends ApiController implements SparkSpringController, CrudController<AccessToken> {

    private final ApiAuthenticationHelper apiAuthenticationHelper;
    private final AccessTokenService accessTokenService;
    private final EntityHashingService entityHashingService;
    private Clock clock;

    @Autowired
    public AccessTokenControllerV1(ApiAuthenticationHelper apiAuthenticationHelper, AccessTokenService accessTokenService, EntityHashingService entityHashingService, Clock clock) {
        super(ApiVersion.v1);
        this.apiAuthenticationHelper = apiAuthenticationHelper;
        this.accessTokenService = accessTokenService;
        this.entityHashingService = entityHashingService;
        this.clock = clock;
    }

    @Override
    public String controllerBasePath() {
        return AccessTokenAPI.BASE;
    }

    @Override
    public void setupRoutes() {
        path(controllerBasePath(), () -> {
            before("", mimeType, this::setContentType);
            before("/*", mimeType, this::setContentType);
            before("", mimeType, this::verifyContentType);
            before("/*", mimeType, this::verifyContentType);
            before("", mimeType, apiAuthenticationHelper::checkSecurityEnabledAndReturn403);
            before("/*", mimeType, apiAuthenticationHelper::checkSecurityEnabledAndReturn403);

            before("", mimeType, apiAuthenticationHelper::checkUserAnd403);
            before("/*", mimeType, apiAuthenticationHelper::checkUserAnd403);

            get("", mimeType, this::getAllTokensForUser);
            get(AccessTokenAPI.GET_TOKEN, mimeType, this::getToken);
            post(AccessTokenAPI.CREATE_TOKEN, mimeType, this::createToken);
            delete(AccessTokenAPI.DELETE_TOKEN, mimeType, this::deleteToken);
            exception(RecordNotFoundException.class, this::notFound);
        });
    }

    public String getAllTokensForUser(Request request, Response response) throws IOException {
        List<AccessToken> allTokens = accessTokenService.getAllTokensForUser(currentUserId(request));

        return writerForTopLevelObject(request, response,
                outputWriter -> AccessTokensRepresenter.toJSON(outputWriter, allTokens));
    }

    public String getToken(Request request, Response response) throws IOException {
        String tokenName = request.params("name");

        Optional<AccessToken> optToken = accessTokenService.getAllTokensForUser(currentUserId(request))
                .stream()
                .filter((AccessToken t) -> t.getName().equals(tokenName))
                .findFirst();

        if (!optToken.isPresent()) {
            throw HaltApiResponses.haltBecauseNotFound(String.format("The token with name '%s' was not found.", tokenName));
        }

        return writerForTopLevelObject(request, response, writer -> AccessTokenRepresenter.toJSON(writer, optToken.get()));
    }

    public String createToken(Request request, Response response) {
        JsonReader reader = GsonTransformer.getInstance().jsonReaderFrom(request.body());
        AccessToken accessToken = AccessTokenRepresenter.fromJSON(reader, clock);

        response.type(TEXT_PLAIN);
        response.raw().setCharacterEncoding("utf-8");

        return accessTokenService.createToken(accessToken);
    }

    public String deleteToken(Request request, Response response) throws IOException {
        String tokenName = request.params("name");

        Optional<AccessToken> optToken = accessTokenService.getAllTokensForUser(currentUserId(request))
                .stream()
                .filter((AccessToken t) -> t.getName().equals(tokenName))
                .findFirst();

        if (!optToken.isPresent()) {
            throw HaltApiResponses.haltBecauseNotFound(String.format("The token with name '%s' was not found.", tokenName));
        }

        HttpLocalizedOperationResult result = new HttpLocalizedOperationResult();

        if (accessTokenService.deleteToken(tokenName)) {
            result.setMessage(LocalizedMessage.resourceDeleteSuccessful("access token", optToken.get().getName()));
        }

        return renderHTTPOperationResult(result, request, response);
    }

    @Override
    public String etagFor(AccessToken entityFromServer) {
        return entityHashingService.md5ForEntity(entityFromServer);
    }

    @Override
    public AccessToken doGetEntityFromConfig(String name) {
        return null; // to be implemented
    }

    @Override
    public AccessToken getEntityFromRequestBody(Request req) {
        return null; // to be implemented
    }

    @Override
    public String jsonize(Request req, AccessToken o) {
        return null; // to be implemented
    }

    @Override
    public JsonNode jsonNode(Request req, AccessToken o) throws IOException {
        return null; // to be implemented
    }
}
