/*
 * Copyright 2017 ThoughtWorks, Inc.
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

package com.thoughtworks.go.remote.work;

import com.thoughtworks.go.domain.ArtifactPlan;
import com.thoughtworks.go.plugin.access.artifact.ArtifactExtension;
import com.thoughtworks.go.util.GoConstants;
import com.thoughtworks.go.work.GoPublisher;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ArtifactsPublisher implements Serializable {
    private ArtifactPlanFilter artifactPlanFilter;
    private ArtifactExtension artifactExtension;

    public ArtifactsPublisher() {
    }

    public ArtifactsPublisher(ArtifactPlanFilter artifactPlanFilter, ArtifactExtension artifactExtension) {
        this.artifactPlanFilter = artifactPlanFilter;
        this.artifactExtension = artifactExtension;
    }

    public ArtifactsPublisher(ArtifactExtension artifactExtension) {
        this(new ArtifactPlanFilter(), artifactExtension);
    }

    public void publishArtifacts(GoPublisher goPublisher, File workingDirectory, List<ArtifactPlan> assignment) {
        final List<ArtifactPlan> pluggableArtifactPlans = artifactPlanFilter.getPluggableArtifactPlans(assignment);


        final List<ArtifactPlan> mergedPlans = artifactPlanFilter.getBuiltInMergedArtifactPlans(assignment);

        List<ArtifactPlan> failedArtifact = new ArrayList<>();
        for (ArtifactPlan artifactPlan : mergedPlans) {
            try {
                artifactPlan.publish(goPublisher, workingDirectory);
            } catch (Exception e) {
                failedArtifact.add(artifactPlan);
            }
        }


        if (!failedArtifact.isEmpty()) {
            StringBuilder builder = new StringBuilder();
            for (ArtifactPlan artifactPlan : failedArtifact) {
                artifactPlan.printArtifactInfo(builder);
            }
            throw new RuntimeException(String.format("[%s] Uploading finished. Failed to upload %s", GoConstants.PRODUCT_NAME, builder));
        }
    }
}
