# The standalone gateway binary as a scratch image. The binary is built
# by CI as a static x86_64 musl executable (see .github/workflows/ci.yml)
# and dropped into build/ as `gateway` before `docker build`.
FROM scratch
COPY gateway /gateway
ENTRYPOINT ["/gateway"]
