# Start with a rust alpine image
FROM rust:alpine
# This is important, see https://github.com/rust-lang/docker-rust/issues/85
ENV RUSTFLAGS="-C target-feature=-crt-static"
# if needed, add additional dependencies here
RUN apk add --no-cache musl-dev openssl-dev protoc protobuf-dev
# set the workdir and copy the source into it
WORKDIR /app
COPY ./ /app
# do a release build
RUN cargo build --release --bin rest_server
RUN strip target/release/rest_server

# use a plain alpine image, the alpine version needs to match the builder
FROM alpine
# if needed, install additional dependencies here
RUN apk add --no-cache libgcc
# copy the binary into the final image
COPY --from=0 /app/target/release/rest_server .
# set the binary as entrypoint
ENTRYPOINT ["/rest_server"]
