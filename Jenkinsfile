/*
 * Copyright 2024 gematik GmbH
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

@Library('gematik-jenkins-shared-library') _

def CREDENTIAL_ID_GEMATIK_GIT = 'svc_gitlab_prod_credentials'
def BRANCH = 'main'
def JIRA_PROJECT_ID = 'TES'
def GITLAB_PROJECT_ID = '1845'
def TAG_NAME = "ci/build"
def POM_PATH = 'pom.xml'

def APP = 'popp-server-mockservice'
def IMAGE_NAME = "testtools/${APP}"
def IMAGE_VERSION = 'latest'
def VERSION = 'latest'
def BUILD_ARGS = "--build-arg APP=${APP}"
def DOCKER_TARGET_REGISTRY = dockerGetGematikRegistry('EUWEST3')

pipeline {
    options {
        disableConcurrentBuilds()
    }
    agent { label 'k8-maven-small' }
    tools {
        maven 'Default'
    }
    stages {

        stage('Initialize') {
            steps {
                useJdk('OPENJDK17')
            }
        }

        stage('gitCreateBranch') {
            when { branch BRANCH }
            steps {
                gitCreateBranch()
            }
        }

        stage('Build') {
            steps {
                mavenBuild(POM_PATH)
            }
        }

        stage('Test') {
            steps {
                mavenTest(POM_PATH)
            }
        }

        stage('Deploy') {
            when { branch BRANCH }
            steps {
                mavenDeploy(POM_PATH)
            }
        }

        stage('Build Docker Image') {
            steps {
                dockerBuild(IMAGE_NAME, VERSION, IMAGE_VERSION, BUILD_ARGS, 'docker/Dockerfile', DOCKER_TARGET_REGISTRY)
            }
        }

        stage('Push Docker Image') {
            when {
                branch BRANCH
            }
            steps {
                dockerPushImage(IMAGE_NAME, VERSION, 'testtools-gar-writer', DOCKER_TARGET_REGISTRY)
            }
        }

        stage('Cleanup Docker Image') {
            steps {
                dockerRemoveLocalImage(IMAGE_NAME, VERSION, DOCKER_TARGET_REGISTRY)
            }
        }
    }
}
