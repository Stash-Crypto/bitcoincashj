[![Build Status](https://travis-ci.org/bitcoinj-cash/bitcoinj.png?branch=cash-0.14)](https://travis-ci.org/Stash-Crypto/bitcoincashj)   [![Coverage Status](https://coveralls.io/repos/github/Stash-Crypto/bitcoincashj/badge.svg?branch=release-0.14)](https://coveralls.io/github/Stash-Crypto/bitcoincashj?branch=release-0.14) [![Javadocs](http://www.javadoc.io/badge/org.bitcoincashj/bitcoincashj-core.svg)](http://www.javadoc.io/doc/org.bitcoincashj/bitcoincashj-core)

### Welcome to blockchainj

This library is a fork of Mike Hearn's original bitcoinj library aimed at supporting the Bitcoin and Bitcoin cash eco-system.

It allows maintaining a wallet and sending/receiving transactions without needing a full blockchain node. It comes with full documentation and some example apps showing how to use it.

Release notes are [here](docs/Releases.md).

### Technologies

* Java 7 for the core modules, Java 8 for everything else
* [Gradle 3.4+](https://gradle.org/) - for building the project
* [Google Protocol Buffers](https://github.com/google/protobuf) - for use with serialization and hardware communications

### Getting started

To get started, it is best to have the latest JDK and Gradle installed. The HEAD of the `master` branch contains the latest development code and various production releases are provided on feature branches.

#### Building from the command line

To perform a full build use
```
gradle clean build
```
You can also run
```
gradle javadoc
```
to generate the JavaDocs.

The outputs are under the `build` directory.

#### Building from an IDE

Alternatively, just import the project using your IDE. [IntelliJ](http://www.jetbrains.com/idea/download/) has Gradle integration built-in and has a free Community Edition. Simply use `File | New | Project from Existing Sources` and locate the `build.gradle` in the root of the cloned project source tree.

### Example applications

These are found in the `examples` module.

### Where next?

Now you are ready to [follow the tutorial](https://bitcoinj.github.io/getting-started).

