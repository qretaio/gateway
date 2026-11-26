# The standalone gateway binary as a scratch image. CI builds a static
# x86_64 musl executable and stages it at build/gateway before docker build.
FROM scratch
COPY build/gateway /gateway
ENTRYPOINT ["/gateway"]
