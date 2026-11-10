FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:17-jre
RUN useradd --create-home investigator
WORKDIR /cases
COPY --from=build /src/target/cloudtrace.jar /opt/cloudtrace.jar
USER investigator
ENTRYPOINT ["java", "-Djava.awt.headless=true", "-jar", "/opt/cloudtrace.jar"]
