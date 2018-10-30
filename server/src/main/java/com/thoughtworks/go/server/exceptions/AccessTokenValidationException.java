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

package com.thoughtworks.go.server.exceptions;

public class AccessTokenValidationException extends RuntimeException {

    public AccessTokenValidationException(String message) {
        super(message);
    }

    public static void throwBecauseInvalidDescription() {
        throw new AccessTokenValidationException("Token description must not exceed 512 characters.");
    }

    public static void throwBecauseInvalidName() {
        throw new AccessTokenValidationException("Token name must not exceed 255 characters.");
    }

    public static void throwBecauseInvalidUserId(Long userId) {
        throw new AccessTokenValidationException(String.format("User id with value '%s' is not permitted. Access Token must be associated with a valid user-id.", userId));
    }
}
