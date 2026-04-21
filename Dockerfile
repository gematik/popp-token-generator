FROM amazoncorretto:21-alpine-jdk

ARG COMMIT_HASH
ARG VERSION

LABEL de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="PoppTokenGenerator" \
      de.gematik.git-repo-name="https://github.com/gematik/popp-token-generator" \
      de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION

WORKDIR /app

EXPOSE 80

COPY ./target/popp-token-generator-*-*.jar /app/popp-token-generator.jar

ENTRYPOINT ["java", "-jar", "/app/popp-token-generator.jar"]
