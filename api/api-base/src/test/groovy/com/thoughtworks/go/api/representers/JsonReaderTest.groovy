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

package com.thoughtworks.go.api.representers

import com.thoughtworks.go.api.util.GsonTransformer
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import spark.HaltException

import static org.assertj.core.api.AssertionsForClassTypes.assertThat
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType

class JsonReaderTest {

  @Nested
  class String {
    @Test
    void 'should read valid value'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "bar"])
      assertThat(reader.getString("foo")).isEqualTo("bar")
    }

    @Test
    void 'should read optional value when present'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "bar"])
      assertThat(reader.optString("foo").get()).isEqualTo("bar")
    }

    @Test
    void 'should read optional value when absent'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["xyz": "bar"])
      assertThat(reader.optString("foo").isPresent()).isFalse()
    }

    @Test
    void 'should blow up if reading wrong type'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": ["bar": "baz"]])
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.getString("foo") })
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.optString("foo") })
    }
  }

  @Nested
  class JsonArray {

    @Test
    void 'should read optional value when present'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": ["bar", "baz"]])
      def expectedArray = new com.google.gson.JsonArray()
      expectedArray.add("bar")
      expectedArray.add("baz")
      assertThat(reader.optJsonArray("foo").get()).isEqualTo(expectedArray)
    }

    @Test
    void 'should read optional value when absent'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["xyz": "bar"])
      assertThat(reader.optJsonArray("foo").isPresent()).isFalse()
    }

    @Test
    void 'should blow up if reading wrong type'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "bar"])
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.optJsonArray("foo") })
    }
  }

  @Nested
  class JsonObject {

    @Test
    void 'should read json object'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": ["bar": "baz"]])
      def newReader = reader.readJsonObject("foo")

      assertThat(newReader.getString("bar")).isEqualTo("baz")
    }

    @Test
    void 'should optionally read json object'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": ["bar": "baz"]])
      def newReader = reader.optJsonObject("other")

      assertThat(newReader.isPresent()).isFalse()
    }

    @Test
    void 'should blow up if reading wrong type'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "bar"])
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.optJsonObject("foo") })
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.readJsonObject("foo") })
    }
  }

  @Nested
  class OptLong {
    @Test
    void 'should read long value'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "12345"])
      def actualValue = reader.optLong("foo")

      assertThat(actualValue).isEqualTo(Optional.of(12345L))
    }

    @Test
    void 'should read empty optional value if property does not exist'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["bar":"baz"])
      def actualValue = reader.optLong("foo")

      assertThat(actualValue).isEqualTo(Optional.empty())
    }
  }


  @Nested
  class Int {
    @Test
    void 'should read valid int value'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": 12])
      assertThat(reader.getInt("foo")).isEqualTo(12)
    }

    @Test
    void 'should blow up if reading wrong type'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "bar"])
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.getInt("foo") })
      assertThatExceptionOfType(HaltException.class)
        .isThrownBy({ reader.optInt("foo") })
    }

    @Test
    void 'should read optional int value'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["foo": "12345"])
      def actualValue = reader.optInt("foo")

      assertThat(actualValue).isEqualTo(Optional.of(12345))
    }

    @Test
    void 'should read empty optional value if property does not exist'() {
      def reader = GsonTransformer.instance.jsonReaderFrom(["bar":"baz"])
      def actualValue = reader.optInt("foo")

      assertThat(actualValue).isEqualTo(Optional.empty())
    }
  }
}
