#!/bin/bash

# Set current directory as working directory
cd "${0%/*}"

# Download the app binary from FDroid
wget -nc "https://f-droid.org/repo/com.example.root.analyticaltranslator_6.apk"

# Download the OKHTTP library binaries from Maven
okhttp3_versions=$(curl https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/maven-metadata.xml 2>&1 | perl -nle 'print $1 if m{<version>(.*)</version>}' 2>/dev/null)

for v in $okhttp3_versions;
do
    wget -nc "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/$v/okhttp-$v.jar" -O "okhttp_$v.jar"
done

okhttp2_versions=$(curl https://repo1.maven.org/maven2/com/squareup/okhttp/okhttp/maven-metadata.xml 2>&1 | perl -nle 'print $1 if m{<version>(.*)</version>}' 2>/dev/null)

for v in $okhttp2_versions;
do
    wget -nc "https://repo1.maven.org/maven2/com/squareup/okhttp/okhttp/$v/okhttp-$v.jar" -O "okhttp_$v.jar"
done


