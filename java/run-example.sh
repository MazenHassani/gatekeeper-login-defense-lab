#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -d target/classes ]; then
  echo 'Build first: mvn -f java/pom.xml package' >&2
  exit 1
fi
mkdir -p target/example
javac --release 21 -cp target/classes -d target/example example/ExampleServer.java
exec java -cp target/classes:target/example dev.gatekeeper.example.ExampleServer "$PWD/example"
