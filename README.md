# go-modiff 📔

[![CircleCI](https://circleci.com/gh/saschagrunert/go-modiff.svg?style=shield)](https://circleci.com/gh/saschagrunert/go-modiff)
[![codecov](https://codecov.io/gh/saschagrunert/go-modiff/branch/main/graph/badge.svg)](https://codecov.io/gh/saschagrunert/go-modiff)

## Command line tool for diffing go module dependency changes between versions

## Usage

The tool can be installed via:

```shell
go get github.com/saschagrunert/go-modiff/cmd/go-modiff
```

After that, the application can be used like this:

```shell
> go-modiff -r github.com/cri-o/cri-o -f v1.15.0
INFO Setting up repository github.com/cri-o/cri-o
INFO Retrieving modules of v1.15.0
INFO Retrieving modules of master
INFO 385 modules found
INFO 1 modules added
INFO 11 modules changed
INFO 0 modules removed
INFO Done, the result will be printed to `stdout`
```

```markdown
# Dependencies

## Added

- github.com/creack/pty: v1.1.7

## Changed

- github.com/containerd/go-runc: 7d11b49 → 9007c24
- github.com/containerd/project: 831961d → 7fb81da
- github.com/containerd/ttrpc: 2a805f7 → 1fb3814
- github.com/containers/libpod: 5e42bf0 → v1.4.4
- github.com/containers/storage: v1.12.12 → v1.12.13
- github.com/godbus/dbus: 2ff6f7f → 8a16820
- github.com/kr/pty: v1.1.5 → v1.1.8
- golang.org/x/net: 3b0461e → da137c7
- golang.org/x/sys: c5567b4 → 04f50cd
- google.golang.org/grpc: v1.21.1 → v1.22.0
- honnef.co/go/tools: e561f67 → ea95bdf

## Removed

_Nothing has changed._
```

It is also possible to add diff links to the markdown output via `--link, -l`.
The output would then look like this:

```markdown
# Dependencies

## Added

- github.com/shurcooL/httpfs: [8d4bc4b](https://github.com/shurcooL/httpfs/tree/8d4bc4b)
- github.com/shurcooL/vfsgen: [6a9ea43](https://github.com/shurcooL/vfsgen/tree/6a9ea43)

## Changed

- github.com/onsi/ginkgo: [v1.8.0 → v1.9.0](https://github.com/onsi/ginkgo/compare/v1.8.0...v1.9.0)
- github.com/onsi/gomega: [v1.5.0 → v1.6.0](https://github.com/onsi/gomega/compare/v1.5.0...v1.6.0)
- github.com/saschagrunert/ccli: [e981d95 → 05e6f25](https://github.com/saschagrunert/ccli/compare/e981d95...05e6f25)
- github.com/urfave/cli: [v1.20.0 → 23c8303](https://github.com/urfave/cli/compare/v1.20.0...23c8303)

## Removed

- github.com/saschagrunert/go-docgen: [v0.1.3](https://github.com/saschagrunert/go-docgen/tree/v0.1.3)
```

### Local repositories

If `--repository` is omitted, then the tool detects the repository itself. It
looks for the top level of the git repository which contains the current
directory and reads the module path from its `go.mod` file:

```shell
> go-modiff -f v1.3.4 -t v1.3.5
INFO Detected go module github.com/saschagrunert/go-modiff in git repository /home/user/go-modiff
INFO Detected repository github.com/saschagrunert/go-modiff
INFO Using /home/user/go-modiff as our reference repository
```

The repository name comes from the URL of the `origin` remote and falls back to
the module path if there is no usable remote. The local repository is also used
as the reference clone, so no network clone is necessary. Both revisions are
checked out into detached worktrees, which means that the current branch can be
compared as well.

The detection fails if the current directory is not part of a git repository or
if that repository holds no `go.mod` file.

### Arguments

The following command line arguments are currently supported:

| Argument              | Description                                                                    |
| --------------------- | ------------------------------------------------------------------------------ |
| `--repository, -r`    | repository to be used, like: github.com/owner/repo (default: the local module)  |
| `--reference-clone`   | path to an existing clone to use as the reference (default: the local one)      |
| `--from, -f`          | the start of the comparison (any valid git rev) (default: "master")            |
| `--to, -t`            | the end of the comparison (any valid git rev) (default: "master")              |
| `--link, -l`          | add diff links to the markdown output (default: false)                          |
| `--header-level, -i`  | add a higher markdown header level depth (default: 1)                           |
| `--include-indirect, -I` | include indirect imports (default: false)                                   |
| `--include-empty, -e` | include empty added/changed/removed sections (default: false)                   |
| `--debug, -d`         | enable debug output (default: false)                                           |

## GitHub Action

The repository ships a GitHub Action which runs the tool against an already
checked out repository. It detects the compared revisions on its own: `to`
becomes the currently checked out commit and `from` becomes the most recent
release tag reachable from it.

```yaml
- uses: actions/checkout@v4
  with:
    # the full history and all tags are required to compare revisions
    fetch-depth: 0

- uses: actions/setup-go@v5
  with:
    go-version-file: go.mod

- uses: saschagrunert/go-modiff@v2
  id: modiff

- run: echo "$MARKDOWN"
  env:
    MARKDOWN: ${{ steps.modiff.outputs.markdown }}
```

The action requires that the repository has already been cloned by a previous
step and that Go is available on the runner. Check out with `fetch-depth: 0`,
otherwise neither the release tags nor the history behind them are present. The
action fetches them itself if the checkout turns out to be shallow, which needs
the credentials that `actions/checkout` persists by default.

Debug output is enabled automatically when the workflow runs with debug
logging, so re-running a job with "Enable debug logging" needs no change to the
workflow.

### Action inputs

| Input                 | Default            | Description                                                              |
| --------------------- | ------------------ | ------------------------------------------------------------------------ |
| `working-directory`   | `.`                | directory of the checked out go module                                   |
| `repository`          | the local module   | repository to be used, like `github.com/owner/repo`                      |
| `reference-clone`     | the local one      | path to an existing clone to use as the reference                        |
| `from`                | latest release tag | the start of the comparison, any valid git rev                           |
| `to`                  | the current commit | the end of the comparison, any valid git rev                             |
| `tag-pattern`         | `v*`               | glob matching the release tags considered while detecting `from`          |
| `include-prereleases` | `false`            | consider pre-release tags, like `v1.0.0-rc.1`, while detecting `from`     |
| `link`                | `true`             | add diff links to the markdown output                                    |
| `header-level`        | `1`                | the markdown header level depth of the output                            |
| `include-indirect`    | `false`            | include indirect imports                                                 |
| `include-empty`       | `false`            | include empty added/changed/removed sections                             |
| `debug`               | `false`            | enable debug output, also enabled by workflow debug logging              |
| `fetch-history`       | `true`             | fetch the full history and all tags if the checkout lacks them            |
| `output-file`         | below `RUNNER_TEMP` | file the markdown is written to                                         |
| `step-summary`        | `true`             | append the markdown to the job summary                                   |

### Action outputs

| Output       | Description                                             |
| ------------ | ------------------------------------------------------- |
| `markdown`   | the rendered markdown dependency diff                   |
| `file`       | path of the file the markdown was written to            |
| `from`       | the git rev the comparison started at                   |
| `to`         | the git rev the comparison ended at                     |
| `repository` | the repository the diff was created for                 |
| `empty`      | `true` if no dependency was added, changed or removed   |

A common use is adding the diff to a release body or a pull request comment:

```yaml
- uses: saschagrunert/go-modiff@v2
  id: modiff
  with:
    header-level: '2'

- if: steps.modiff.outputs.empty == 'false'
  run: gh pr comment "$NUMBER" --body "$MARKDOWN"
  env:
    GH_TOKEN: ${{ github.token }}
    NUMBER: ${{ github.event.pull_request.number }}
    MARKDOWN: ${{ steps.modiff.outputs.markdown }}
```

## Contributing

You want to contribute to this project? Wow, thanks! So please just fork it and
send me a pull request.
