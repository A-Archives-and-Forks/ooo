# Static build with musl -> final image from `scratch`: the binary only.
# Nothing else is needed at runtime: no TLS out, no DNS, no files, no clock
# data, so there is nothing left in the image for anyone to reach.
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY index.html ./
COPY src src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/ooo-server /ooo-server
# The container boundary is the isolation here, so bind every interface inside
# it and let compose decide what the host exposes. The default 127.0.0.1 would
# be unreachable from outside the container.
ENV OOO_ADDR=0.0.0.0:8888
USER 65534:65534
EXPOSE 8888
ENTRYPOINT ["/ooo-server"]
