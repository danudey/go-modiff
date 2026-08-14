# NAME

go-modiff - Command line tool for diffing go module dependency changes between versions

# SYNOPSIS

go-modiff

```
[--debug|-d]
[--from|-f]=[value]
[--header-level|-i]=[value]
[--help|-h]
[--include-empty|-e]
[--include-indirect|-I]
[--link|-l]
[--reference-clone]=[value]
[--repository|-r]=[value]
[--to|-t]=[value]
[--version|-v]
```

**Usage**:

```
Command line tool for diffing go module dependency changes between versions
```

# GLOBAL OPTIONS

**--debug, -d**: enable debug output

**--from, -f**="": the start of the comparison, any valid git rev (default: "master")

**--header-level, -i**="": add a higher markdown header level depth (default: 1)

**--help, -h**: show help

**--include-empty, -e**: include empty added/changed/removed sections

**--include-indirect, -I**: include indirect imports

**--link, -l**: add diff links to the markdown output

**--reference-clone**="": path to an existing clone to use as the reference

**--repository, -r**="": repository to be used, like: github.com/owner/repo (defaults to the go module of the local git repository)

**--to, -t**="": the end of the comparison, any valid git rev (default: "master")

**--version, -v**: print the version


# COMMANDS

## docs, d

generate the markdown or man page documentation and print it to stdout

**--help, -h**: show help

**--man**: print the man version

**--markdown**: print the markdown version

### help, h

Shows a list of commands or help for one command

## fish, f

generate the fish shell completion and print it to stdout

**--help, -h**: show help

### help, h

Shows a list of commands or help for one command

## help, h

Shows a list of commands or help for one command
