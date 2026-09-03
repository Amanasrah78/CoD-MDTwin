FROM golang:1.13-buster

ARG WAVE_COMMIT=3b90ec17ea9dde89e995a9a46222a93df0f992d4
ENV GO111MODULE=off

WORKDIR /go/src/github.com/immesys/wave

# Pin both the public WAVE source and its legacy dependency manager.
RUN git clone https://github.com/immesys/wave.git . \
    && git checkout --detach "${WAVE_COMMIT}" \
    && git clone --branch v0.5.4 --depth 1 https://github.com/golang/dep.git /go/src/github.com/golang/dep \
    && go install github.com/golang/dep/cmd/dep \
    && dep ensure -vendor-only

# WAVE's pinned JEDI dependency uses CGo and requires its native static
# pairing library before the Go benchmark can be linked.
RUN cd vendor/github.com/ucbrise/jedi-pairing \
    && make CXX=g++ CXXFLAGS="-std=c++17 -I./include -O3 -fPIC"

COPY wave_depth_comparison_test.go ./paper_benchmarks/

RUN go test -c -o /usr/local/bin/wave-paper-benchmarks ./paper_benchmarks

CMD ["/usr/local/bin/wave-paper-benchmarks", "-test.run", "^TestWaveDepthComparison$", "-test.v"]
