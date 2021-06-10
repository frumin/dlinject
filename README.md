# dlinject

A simple command line utility to inject an arbitrary `dylib` into a running process. It runs continously and re-injects the code if the target process quits or a new intance is spawned.

## Usage

```bash
./dlinject 'My Process' /path/to/library.dylib
```
