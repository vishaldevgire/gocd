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

package com.thoughtworks.go.apiv1.accesstoken

import com.thoughtworks.go.api.SecurityTestTrait
import com.thoughtworks.go.api.spring.ApiAuthenticationHelper
import com.thoughtworks.go.config.exceptions.RecordNotFoundException
import com.thoughtworks.go.server.domain.accesstoken.AccessToken
import com.thoughtworks.go.server.domain.accesstoken.AccessTokenInfo
import com.thoughtworks.go.server.service.AccessTokenService
import com.thoughtworks.go.server.service.AdminsConfigService
import com.thoughtworks.go.server.service.EntityHashingService
import com.thoughtworks.go.spark.ControllerTrait
import com.thoughtworks.go.spark.NonAnonymousUserSecurity
import com.thoughtworks.go.spark.SecurityServiceTrait
import com.thoughtworks.go.util.TestingClock
import groovy.json.JsonBuilder
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.Mock

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyLong
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.when
import static org.mockito.MockitoAnnotations.initMocks

class AccessTokenControllerV1Test implements SecurityServiceTrait, ControllerTrait<AccessTokenControllerV1> {

  @Mock
  private AdminsConfigService adminsConfigService
  @Mock
  private EntityHashingService entityHashingService
  @Mock
  private AccessTokenService accessTokenService

  @Override
  AccessTokenControllerV1 createControllerInstance() {
    new AccessTokenControllerV1(new ApiAuthenticationHelper(securityService, goConfigService), accessTokenService, entityHashingService, new TestingClock())
  }

  @BeforeEach
  void setup() {
    initMocks(this)
  }

  @Nested
  class Index {

    @Nested
    class Security implements SecurityTestTrait, NonAnonymousUserSecurity {
      @Override
      String getControllerMethodUnderTest() {
        return 'listAllTokensForUser'
      }

      @Override
      void makeHttpCall() {
        getWithApiHeader(controller.controllerPath())
      }

      @Override
      @Test
      void 'should allow nobody with security disabled'() {
        disableSecurity()

        makeHttpCall()
        assertThatResponse()
          .isForbidden()
          .hasJsonMessage("Could not process request as security is disabled.")
      }

    }

    @Nested
    class AsAUser {
      @BeforeEach
      void setUp() {
        enableSecurity()
        loginAsUser()
      }

      @Test
      void 'should list all tokens'() {

        def expectedResponseBody = [
          "_links"   : [
            "self": [
              "href": "http://test.host/go/api/tokens"
            ],
            "doc" : [
              "href": "https://api.gocd.org/current/#api-access-token"
            ],
            "find": [
              "href": "http://test.host/go/api/tokens/:name"
            ]
          ],
          "_embedded": [
            "tokens": [
              [
                "_links"     : [
                  "self": [
                    "href": "http://test.host/go/api/tokens/PersonToken"
                  ],
                  "doc" : [
                    "href": "https://api.gocd.org/current/#api-access-token"
                  ],
                  "find": [
                    "href": "http://test.host/go/api/tokens/:name"
                  ]
                ],
                "name"       : "PersonToken",
                "description": "Personal Token",
                "expires_at" : 987654321
              ],
              [
                "_links"     : [
                  "self": [
                    "href": "http://test.host/go/api/tokens/WorkToken"
                  ],
                  "doc" : [
                    "href": "https://api.gocd.org/current/#api-access-token"
                  ],
                  "find": [
                    "href": "http://test.host/go/api/tokens/:name"
                  ]
                ],
                "name"       : "WorkToken",
                "description": "Token for work only",
                "expires_at" : 876543219
              ]
            ]
          ]
        ]

        def token1 = new AccessToken("PersonToken", "Personal Token", 987654321)
        def token2 = new AccessToken("WorkToken", "Token for work only", 876543219)

        when(accessTokenService.listAllTokensForUser(currentUserLoginId())).thenReturn([token1, token2])

        getWithApiHeader(controller.controllerPath())

        assertThatResponse()
          .isOk()
          .hasContentType(controller.mimeType)
          .hasJsonBody(new JsonBuilder(expectedResponseBody).toString())
      }
    }
  }

  @Nested
  class GetToken {

    @Nested
    class Security implements SecurityTestTrait, NonAnonymousUserSecurity {
      @Override
      String getControllerMethodUnderTest() {
        return 'getToken'
      }

      @Override
      void makeHttpCall() {
        getWithApiHeader(controller.controllerPath("1234"))
      }

      @Override
      @Test
      void 'should allow nobody with security disabled'() {
        disableSecurity()

        makeHttpCall()
        assertThatResponse()
          .isForbidden()
          .hasJsonMessage("Could not process request as security is disabled.")
      }
    }

    @Nested
    class AsAUser {
      @BeforeEach
      void setUp() {
        enableSecurity()
        loginAsUser()
      }

      @Test
      void 'should return token'() {
        def expectedJson = [
          "_links"     : [
            "self": [
              "href": "http://test.host/go/api/tokens/PersonToken"
            ],
            "doc" : [
              "href": "https://api.gocd.org/current/#api-access-token"
            ],
            "find": [
              "href": "http://test.host/go/api/tokens/:name"
            ]
          ],
          "name"       : "PersonToken",
          "description": "Personal Token",
          "expires_at" : 987654321
        ]

        def token1 = new AccessToken("PersonToken", "Personal Token", 987654321)

        when(accessTokenService.findTokenForUser(currentUserLoginId(), "PersonToken")).thenReturn(Optional.of(token1))

        getWithApiHeader(controller.controllerPath("PersonToken"))

        assertThatResponse()
          .isOk()
          .hasContentType(controller.mimeType)
          .hasJsonBody(new JsonBuilder(expectedJson).toString())
      }

      @Test
      void 'should return 404 for a unknown token'() {
        when(accessTokenService.findTokenForUser(currentUserLoginId(), "UnknownToken")).thenReturn(Optional.empty())

        getWithApiHeader(controller.controllerPath("UnknownToken"))

        def expectedJson = [
          "message": "The token with name 'UnknownToken' was not found."
        ]

        assertThatResponse()
          .isNotFound()
          .hasContentType(controller.mimeType)
          .hasJsonBody(new JsonBuilder(expectedJson).toString())
      }
    }
  }

  @Nested
  class DeleteToken {

    @Nested
    class Security implements SecurityTestTrait, NonAnonymousUserSecurity {
      @Override
      String getControllerMethodUnderTest() {
        return 'deleteToken'
      }

      @Override
      void makeHttpCall() {
        deleteWithApiHeader(controller.controllerPath("1234"))
      }

      @Override
      @Test
      void 'should allow nobody with security disabled'() {
        disableSecurity()

        makeHttpCall()
        assertThatResponse()
          .isForbidden()
          .hasJsonMessage("Could not process request as security is disabled.")
      }
    }

    @Nested
    class AsAUser {
      @BeforeEach
      void setUp() {
        enableSecurity()
        loginAsUser()
      }

      @Test
      void 'should delete token'() {
        def expectedJson = [
          "message": "The access token 'PersonToken' was deleted successfully."
        ]

        deleteWithApiHeader(controller.controllerPath("PersonToken"))

        verify(accessTokenService).deleteToken(currentUserLoginId(), "PersonToken")

        assertThatResponse()
          .isOk()
          .hasContentType(controller.mimeType)
          .hasJsonBody(new JsonBuilder(expectedJson).toString())
      }

      @Test
      void 'should return 404 for a unknown token'() {
        def expectedJson = [
          "message": "The token with name 'UnknownToken' was not found."
        ]

        when(accessTokenService.deleteToken(currentUserLoginId(), "UnknownToken"))
          .thenThrow(new RecordNotFoundException("The token with name 'UnknownToken' was not found."))

        deleteWithApiHeader(controller.controllerPath("UnknownToken"))

        assertThatResponse()
          .isNotFound()
          .hasContentType(controller.mimeType)
          .hasJsonBody(new JsonBuilder(expectedJson).toString())
      }
    }
  }

  @Nested
  class CreateToken {

    @Nested
    class Security implements SecurityTestTrait, NonAnonymousUserSecurity {
      @Override
      String getControllerMethodUnderTest() {
        return 'createToken'
      }

      @Override
      void makeHttpCall() {
        postWithApiHeader(controller.controllerPath("generate"), [:])
      }

      @Override
      @Test
      void 'should allow nobody with security disabled'() {
        disableSecurity()

        makeHttpCall()
        assertThatResponse()
          .isForbidden()
          .hasJsonMessage("Could not process request as security is disabled.")
      }
    }

    @Nested
    class AsAUser {
      @BeforeEach
      void setUp() {
        enableSecurity()
        loginAsUser()
      }

      @Test
      void 'should create token'() {
        def json = [
          name            : "personal",
          description     : "A personal token",
          expires_in_hours: 5
        ]

        when(accessTokenService.createToken(anyLong(), any() as AccessTokenInfo)).thenReturn("<token-string>")

        postWithApiHeader(controller.controllerPath("generate"), json)

        assertThatResponse()
          .isOk()
          .hasContentType("text/plain;charset=utf-8")
          .hasBody("<token-string>")
      }

      @Test
      void 'should return 422 when request does not have "expires_in_hours"'() {
        def json = [
          name       : "personal",
          description: "A personal token"
        ]

        postWithApiHeader(controller.controllerPath("generate"), json)

        assertThatResponse()
          .isUnprocessableEntity()
          .hasContentType(controller.mimeType)
          .hasJsonMessage("Json `{\\\"name\\\":\\\"personal\\\",\\\"description\\\":\\\"A personal token\\\"}` does not contain property 'expires_in_hours'")
      }

      @Test
      void 'should return 422 when request does not have property "name"'() {
        def json = [
          description     : "A personal token",
          expires_in_hours: 23
        ]

        postWithApiHeader(controller.controllerPath("generate"), json)

        assertThatResponse()
          .isUnprocessableEntity()
          .hasContentType(controller.mimeType)
          .hasJsonMessage("Json `{\\\"description\\\":\\\"A personal token\\\",\\\"expires_in_hours\\\":23}` does not contain property 'name'")
      }
    }
  }
}
