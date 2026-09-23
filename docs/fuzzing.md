# Fuzzing

The six Go fuzz targets are exposed through `Taskfile.fuzz.yml`, using the same
`fuzz:list`, `fuzz:run`, `fuzz:coverage` and `fuzz:replay` interface as Deckhouse,
Stronghold, storage-volume-data-manager and Prom++.

## CI and image

The integration follows [operator-argo's internal-migrate-to-delivery-kit branch](https://fox.flant.com/deckhouse/delivery/operator-argo/-/tree/internal-migrate-to-delivery-kit),
using delivery-kit `v3.4.0-dk.4` and two shared CI templates from
`deckhouse/3p/deckhouse/modules-gitlab-ci` at `fuzz-build-replay-templates`:

1. `Build_Fuzz.gitlab-ci.yml` provides `.fuzz_build` and `.fuzz_replay`.
   `build_fuzz` builds and pushes `*-fuzz` images, including for merge requests,
   and saves `images_fuzz_tags_werf.json` and a generated child pipeline as
   artifacts. `replay_fuzz` triggers that pipeline and waits for its result.
2. The child includes `Replay_Fuzz.gitlab-ci.yml` at the same ref, replays each
   image's corpus in a separate container and retains failure logs, JSON events,
   seeds and reproduction commands under `fuzz-replay/` for seven days.

Both template refs are kept in sync with the `fuzz_templates_ref` YAML anchor.
Jobs inherit the shared rules: merge requests, default-branch pipelines and
schedules; `CLEANUP_REPO=true` skips them. Registry variables are applied to both
parent jobs so the trigger forwards them to the child pipeline.

Replay restores minimized, recovery and Go cache seeds from
`s3://anomaloys-materials/<project>/<branch-slug>/<component>/`. MR and scheduled
replay use `deckhouse` as the baseline instead of the template's `main`.
Default-branch rules use `CI_COMMIT_REF_SLUG` and enable publication of the build
report to `s3://anomaloys-materials/build-reports/<project>/<branch-slug>/` only
after every replay job succeeds. Replay failures also fail the parent pipeline.

`werf.yaml` builds `distribution-fuzz` on the same ready-made `fuzz-go` base as
operator-argo, tagged `f2625cb04c7c9cf6002b59c49de8e6e22a0be674`. It already
contains Go, Task, Bash, Python, jq and AWS CLI. Delivery-kit installs Go modules
with `packages: type: go-mod`; the checkout also retains `vendor/` and sets
`GOFLAGS=-mod=vendor` so both Task and the shared replay's direct Go commands use
the committed dependency graph. The image exposes `/src` through its working
directory, `FUZZ_WORKDIR` and `/etc/fuzz-workdir`, installs `Taskfile.yml`, and
sets `io.deckhouse.fuzz.engine=go`.

There is no local `fuzz.tmpl`: image builds do not restore corpus or run tests.
S3 access and replay belong to the shared child-pipeline template. Continuous
fuzzing remains the responsibility of the fuzzing platform.

The GitLab project needs a Linux amd64 runner tagged `deckhouse`, with Docker,
Bash 4+, curl and jq, plus access to the shared CI project and the fuzz base
image. CI downloads the pinned delivery-kit release. Set
`DEV_WRITE_REGISTRY`, `MODULES_REGISTRY_LOGIN_DEV` and
`MODULES_REGISTRY_PASSWORD_DEV`, as in operator-argo. The default image repository is
`<DEV_WRITE_REGISTRY>/sys/deckhouse-oss/modules/<CI_PROJECT_NAME>`; override
`MODULES_MODULE_SOURCE`/`MODULES_MODULE_NAME` if this fork uses another namespace.

The child jobs obtain `FUZZ_S3_ENDPOINT`, `FUZZ_S3_ACCESS_KEY` and
`FUZZ_S3_SECRET_KEY` from Vault using the GitLab ID token. The shared template
defaults `VAULT_AUTH_ROLE` to `dh-${CI_PROJECT_NAME}`; authorize that role for
this GitLab project, or override it on `replay_fuzz`. Build jobs do not need S3
credentials. The build logs in to `CI_REGISTRY` with `CI_REGISTRY_USER` and
`CI_REGISTRY_PASSWORD` to read the private fuzz base at `registry.flant.com`.
The `deckhouse/ssdlc/ci-images` project must permit this project's CI job token
to pull the image (including any required job-token allowlist entry).

## Local commands

Use Go 1.25 or later and Task 3.50 or later:

```sh
task --taskfile Taskfile.fuzz.yml fuzz:list
FUZZ_PKG=./registry/proxy FUZZ_TARGET=FuzzProxyCachePoisoning \
  task --taskfile Taskfile.fuzz.yml fuzz:replay
FUZZ_PKG=./registry/proxy FUZZ_TARGET=FuzzProxyCachePoisoning FUZZ_TIME=60s \
  task --taskfile Taskfile.fuzz.yml fuzz:run
FUZZ_PKG=./registry/proxy FUZZ_TARGET=FuzzProxyCachePoisoning \
  FUZZ_COVERAGE_FILE=/tmp/distribution-fuzz-coverage.out \
  task --taskfile Taskfile.fuzz.yml fuzz:coverage
```

`FUZZ_WORKERS` defaults to 4 because the HTTP targets can exhaust ephemeral
ports with excessive parallelism. Without `FUZZ_TIME`, `fuzz:run` continues
until stopped by the platform. The commands use `-mod=vendor` and can run
without downloading application dependencies.

## Existing failures

The current seed corpus reproduces two pre-existing defects:

- `FuzzProxyHeadersClientCert`: an untrusted, expired or unsuitable client leaf
  can inherit trust from another certificate supplied in the chain.
- `FuzzManifestPut/seed#4`: a manifest with an absent schema version produces
  HTTP 500 instead of a client error.

These failures fail replay and block S3 build-report publication; the image
itself is built and pushed before replay. CI does not skip either target or set
`FUZZ_ALLOW_KNOWN_5XX`. For a local investigation of other manifest inputs only,
the existing `FUZZ_ALLOW_KNOWN_5XX=1` switch can bypass the second finding.
