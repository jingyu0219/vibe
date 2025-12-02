# Mattermost bcrypt password hasher

This repository provides a small Java console utility that reproduces the bcrypt hashing
behavior Mattermost 10.11.x uses for password storage (default cost 10). The code is limited
to Java 7 language features so it can be compiled with a Java 1.7 toolchain.

## Build

With a JDK that still supports `-source 1.7 -target 1.7` (e.g., OpenJDK 7 or 8):

```
mkdir -p out
javac -source 1.7 -target 1.7 -d out src/*.java
```

If your local JDK has dropped 1.7 support, simply compile without the flags (the generated
bytecode will match your compiler version but the code itself remains Java 7 compatible):

```
mkdir -p out
javac -d out src/*.java
```

## Usage

Hash a password provided on the command line:

```
java -cp out MattermostPasswordHasher "my-secret"
```

Specify the bcrypt cost factor (matches Mattermost `PasswordHashCost`):

```
java -cp out MattermostPasswordHasher --cost 12 "my-secret"
```

Read the password from standard input:

```
echo "my-secret" | java -cp out MattermostPasswordHasher
```
