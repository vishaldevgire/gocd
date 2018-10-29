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

package com.thoughtworks.go.apiv1.accesstoken.representers

import com.thoughtworks.go.api.util.GsonTransformer
import com.thoughtworks.go.server.domain.accesstoken.AccessTokenInfo
import com.thoughtworks.go.util.TestingClock
import org.junit.jupiter.api.Test

import static org.assertj.core.api.Assertions.assertThat

class AccessTokenInfoRepresenterTest {
  @Test
  void 'should de-serialize json'() {
    def inputJson = [
      name            : "personal",
      description     : "A personal token",
      expires_in_hours: 1234
    ]

    def jsonReader = GsonTransformer.instance.jsonReaderFrom(inputJson)

    AccessTokenInfo accessToken = AccessTokenInfoRepresenter.fromJSON(jsonReader, new TestingClock())

    assertThat(accessToken.getName()).isEqualTo("personal")
    assertThat(accessToken.getDescription()).isEqualTo("A personal token")
    assertThat(accessToken.getExpiresAt()).isEqualTo(1234)
  }

}