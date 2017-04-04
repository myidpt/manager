# Build instructions for Linux

(For Windows and Mac, we recommend using a Linux virtual machine and/or [Vagrant-specific build instructions](build-vagrant.md); Go code compiles on Mac but docker and proxy tests will fail on Mac)

We are using [Bazel 0.4.4](https://github.com/bazelbuild/bazel/releases) as the main build system in Istio Manager. The following command builds all targets in Istio Manager:

    bazel build //...

Bazel uses `BUILD` files to keep track of dependencies between sources.  If you
add a new source file or change the imports  please run the following command
in the repository root to update all `BUILD` files:

    bin/gazelle

Data dependencies such as the ones used by tests require manual declaration in
the `BUILD` files.

## Go tooling compatibility

Istio Manager requires Go1.8+ toolchain.

Bazel build environment is compatible with the standard Golang tooling, except you need to vendorize all dependencies in Istio Manager. If you have successfully built with Bazel, run the following script to put dependencies fetched by Bazel into `vendor` directory:

    bin/init.sh

After running this command, you should be able to use all standard go tools:

    go generate istio.io/manager/...
    go build istio.io/manager/...
    go test -v istio.io/manager/...

_Note_: these commands assume you have placed the repository clone into `$GOPATH`.
