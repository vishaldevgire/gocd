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

package com.thoughtworks.go.apiv1.accesstoken.representers;

import com.thoughtworks.go.api.base.OutputWriter;
import com.thoughtworks.go.api.representers.JsonReader;
import com.thoughtworks.go.domain.AccessToken;
import com.thoughtworks.go.spark.Routes;
import com.thoughtworks.go.util.Clock;

public class AccessTokenRepresenter {
    public static AccessToken fromJSON(JsonReader reader, Clock clock) {
        return new AccessToken(reader.getString("name"),
                reader.optString("description").orElse(null),
                clock.currentDateTime().plusHours(reader.getInt("expires_in_hours")).getMillis());
    }

    public static void toJSON(OutputWriter outputWriter, AccessToken accessToken) {
        outputWriter
                .addLinks(linksWriter -> linksWriter
                        .addLink("self", Routes.AccessTokenAPI.name(accessToken.getName()))
                        .addAbsoluteLink("doc", Routes.AccessTokenAPI.DOC)
                        .addLink("find", Routes.AccessTokenAPI.find()))
                .add("name", accessToken.getName())
                .add("description", accessToken.getDescription())
                .add("expires_at", accessToken.getExpiresAt());
    }
}
