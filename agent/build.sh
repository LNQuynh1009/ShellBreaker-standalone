#!/usr/bin/env bash
# Builds two JARs:
#   shellbreaker-logger.jar — only Logger.class, added to bootstrap CL by the agent
#   shellbreaker-agent.jar  — Agent + ShellTransformer + ASM (stays in app CL)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

ASM_VERSION="9.7"
ASM_JAR="lib/asm-${ASM_VERSION}.jar"

mkdir -p lib build/logger_classes build/agent_classes

if [ ! -f "$ASM_JAR" ]; then
    echo "[build] Downloading ASM ${ASM_VERSION}..."
    curl -fL -o "$ASM_JAR" \
        "https://repo1.maven.org/maven2/org/ow2/asm/asm/${ASM_VERSION}/asm-${ASM_VERSION}.jar"
fi

echo "[build] Compiling Logger (bootstrap JAR)..."
javac -source 11 -target 11 \
    -d build/logger_classes \
    src/com/shellbreaker/Logger.java

echo "[build] Packaging shellbreaker-logger.jar..."
jar cf shellbreaker-logger.jar -C build/logger_classes .

echo "[build] Compiling Agent + ShellTransformer (app JAR)..."
javac -source 11 -target 11 \
    -cp "$ASM_JAR" \
    -d build/agent_classes \
    src/com/shellbreaker/ShellTransformer.java \
    src/com/shellbreaker/Agent.java

echo "[build] Merging ASM into agent JAR..."
( cd build/agent_classes && jar xf "../../$ASM_JAR" )

echo "[build] Packaging shellbreaker-agent.jar..."
jar cfm shellbreaker-agent.jar MANIFEST.MF -C build/agent_classes .

echo "[build] Done:"
echo "  shellbreaker-logger.jar $(du -sh shellbreaker-logger.jar | cut -f1)"
echo "  shellbreaker-agent.jar  $(du -sh shellbreaker-agent.jar  | cut -f1)"
