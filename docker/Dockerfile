FROM amazoncorretto:17-alpine-jdk

WORKDIR /app

EXPOSE 80

COPY target/popp-token-generator-*-SNAPSHOT.jar /app/popp-token-generator.jar

ENTRYPOINT ["java", "-jar", "/app/popp-token-generator.jar"]
