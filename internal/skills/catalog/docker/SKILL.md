```skill
# docker — Sandboxed Tool Testing and Isolation

## Category
Sandboxing & Isolation

## License
Apache 2.0 (Docker Engine / Moby)

## Source
https://github.com/moby/moby (Moby / Docker Engine)

## Purpose
Run transient, privilege-restricted containers that mirror the host OS environment.
Used exclusively for pre-deployment sandbox verification of CLI tools before they
are installed on the real host. Never used to run production workloads or agent
operations themselves.

## Use Cases
- Validate behaviour of a newly acquired or upgraded tool before host deployment
- Observe unexpected network calls, file writes, or process spawns in isolation
- Test tool invocations and confirm output format before integrating into agent code
- Reproduce potential supply-chain compromise behaviour safely

## Determining the Host OS Image

Before launching a sandbox, identify the exact OS and version to mirror:

```bash
# Read the host OS details
cat /etc/os-release

# Example output (Ubuntu 24.04):
# ID=ubuntu
# VERSION_ID="24.04"
# The matching Docker image tag is: ubuntu:24.04
```

## Sandbox Launch Template

All sandbox containers must be launched with the following minimum set of
security restrictions. Deviate only with documented, system-manager-approved
justification.

```bash
# Derive host UID/GID to avoid running as root inside the container
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# Determine the matching host OS image tag (e.g. ubuntu:24.04)
HOST_IMAGE=$(. /etc/os-release && echo "${ID}:${VERSION_ID}")

docker run --rm \
  --user "${HOST_UID}:${HOST_GID}" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --memory 512m \
  --cpus 1 \
  "${HOST_IMAGE}" \
  <tool> <args>
```

### Flag Reference

| Flag | Rationale |
|---|---|
| `--rm` | Automatically remove the container on exit — no persistent state |
| `--user HOST_UID:HOST_GID` | Match host user to avoid UID 0 inside container |
| `--security-opt no-new-privileges` | Prevent privilege escalation via `setuid`/`setgid` binaries |
| `--cap-drop ALL` | Remove all Linux capabilities; add back only what is documented and required |
| `--network none` | Isolate from all networks by default; see note on network access below |
| `--read-only` | Mount root filesystem read-only to prevent unexpected writes |
| `--tmpfs /tmp` | Provide a small, non-executable writable scratch area if the tool requires it |
| `--memory 512m` | Prevent runaway memory consumption |
| `--cpus 1` | Prevent CPU monopolisation |

### When Network Access Is Required

Some tools (e.g. `nmap`, `trivy` DB fetch) need network access. If network access
is genuinely required for the sandbox test:

1. Document the specific network destination the tool will contact and why.
2. Obtain system manager approval before adding `--network` flags.
3. Replace `--network none` with the most restrictive option that still allows
   the test (e.g. a dedicated bridge network with explicit DNS and egress rules).
4. **Never** use `--network host` in the sandbox — it defeats the isolation purpose.

### When Additional Capabilities Are Required

If a specific capability is needed (e.g. `NET_RAW` for raw socket tools):

1. Add only the specific capability: `--cap-add NET_RAW`.
2. Document the requirement in the integration notes for that skill.
3. Do not use `--privileged` — it removes all security boundaries.

## Mounting the Tool Binary

To test a locally compiled or downloaded binary without baking it into an image:

```bash
docker run --rm \
  --user "${HOST_UID}:${HOST_GID}" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --mount type=bind,source=/path/to/tool,target=/usr/local/bin/tool,readonly \
  --mount type=bind,source=/path/to/test/target,target=/scan-target,readonly \
  "${HOST_IMAGE}" \
  /usr/local/bin/tool <args> /scan-target
```

## Verification Checklist

After running the sandbox test, confirm all of the following before deploying
the tool to the host:

- [ ] Tool exited with the expected exit code.
- [ ] Tool output matches the expected format and content.
- [ ] No unexpected network connection attempts (confirmed by `--network none` not
      producing unexpected errors, or by container network logs if network was enabled).
- [ ] No unexpected files written outside `/tmp` (enforced by `--read-only`).
- [ ] No privilege escalation attempts observed in container logs.
- [ ] Tool completed within an expected time bound.

## Safety Notes

- **Never run Mitiga agent operations inside Docker.** Docker is used solely for
  pre-deployment tool validation. The agent itself runs directly on the host.
- **Never use `--privileged`.** This flag bypasses all container security controls
  and is equivalent to running code directly on the host.
- **Never use `--network host`.** It exposes the host's network stack to the container.
- **Image provenance:** Only use official distribution images (e.g. `ubuntu:24.04`,
  `debian:12`) pulled from the Docker Official Images namespace. Verify the image
  digest matches the upstream manifest before first use.
- **Do not persist container state.** All sandbox containers are ephemeral (`--rm`).
  Do not commit containers to new images or share sandbox images.
```
