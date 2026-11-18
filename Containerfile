# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
# SPDX-License-Identifier: EUPL-1.2

# Stage 1: Build stage
FROM docker.io/library/eclipse-temurin:25-jdk-alpine@sha256:c7c3d0bdf7f2bbc5a05a6712ed334d198360105634ea9adf76fca94f381b1e3f AS builder

LABEL maintainer="Digg - Agency for Digital Government"
LABEL description="Build stage for Wallet Authorization Server"

WORKDIR /app

# Download dependencies first, cached while pom.xml is unchanged
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x ./mvnw && \
    ./mvnw dependency:go-offline -B

COPY src ./src

RUN ./mvnw clean package -DskipTests -Dcheckstyle.skip=true -B && \
    java -Djarmode=tools -jar target/*.jar extract --layers --launcher --destination extracted

# Stage 2: Runtime stage, distroless with the nonroot user (65532)
FROM gcr.io/distroless/java25-debian13:nonroot@sha256:8ac5525549d14b8ddd34562f9fc8e6ba4840c995363a1507b17cadf8bb7ab57e AS runtime

LABEL maintainer="Digg - Agency for Digital Government"
LABEL description="Wallet Authorization Server"

WORKDIR /app

COPY --from=builder --chown=65532:65532 /app/extracted/dependencies/ ./
COPY --from=builder --chown=65532:65532 /app/extracted/spring-boot-loader/ ./
COPY --from=builder --chown=65532:65532 /app/extracted/snapshot-dependencies/ ./
COPY --from=builder --chown=65532:65532 /app/extracted/application/ ./

EXPOSE 9000

# JVM options are set directly in ENTRYPOINT since distroless has no shell
ENTRYPOINT ["/usr/bin/java", "-XX:MaxRAMPercentage=75.0", "-Dfile.encoding=UTF-8", "org.springframework.boot.loader.launch.JarLauncher"]
