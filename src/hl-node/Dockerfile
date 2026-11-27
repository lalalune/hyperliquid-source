# syntax=docker/dockerfile:1
# Multi-stage Linux/amd64 source build for independent node #115 `hl-node` workspace.
# Zero proprietary binary downloads; offline Cargo build from repository sources.
# Toolchain matches node #115 `.comment` stamps: rustc 1.95.0, Ubuntu 24.04 runtime.

FROM --platform=linux/amd64 rust:1.95.0-bookworm AS builder

WORKDIR /build
COPY rust-toolchain.toml ./
COPY src ./src

ENV CARGO_BUILD_JOBS=4
ENV CARGO_TARGET_DIR=/build/target

RUN cargo build \
    --offline \
    --locked \
    --release \
    --manifest-path src/hl-node/Cargo.toml \
    --bin hl-node

FROM --platform=linux/amd64 ubuntu:24.04 AS runtime

ARG USERNAME=hluser
ARG USER_UID=10000
ARG USER_GID=10000

RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" -m "${USERNAME}" \
    && mkdir -p "/home/${USERNAME}/hl/data" \
    && chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}/hl"

COPY --from=builder /build/target/release/hl-node /usr/local/bin/hl-node

USER "${USERNAME}"
WORKDIR "/home/${USERNAME}"
VOLUME ["/home/hluser/hl/data"]

EXPOSE 4000-4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/hl-node", "--version"]

ENTRYPOINT ["/usr/local/bin/hl-node"]
CMD ["--chain", "Testnet", "run-non-validator", "--replica-cmds-style", "recent-actions", "--dry-run"]
