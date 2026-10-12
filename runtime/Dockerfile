FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build
WORKDIR /xray
# Immutable upstream source. The extension is source-distributed under MPL-2.0.
RUN git init && git remote add origin https://github.com/XTLS/Xray-core.git \
    && git fetch --depth=1 origin 701af60772cda123492f86e383e1fdba066614a9 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 701af60772cda123492f86e383e1fdba066614a9
COPY runtime/xray-target-selection.patch /tmp/selection.patch
RUN git apply /tmp/selection.patch \
    && go test ./app/router ./app/dns -run '^TestGlivela' -count=1 \
    && mkdir /out \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/xray ./main \
    && cp LICENSE /out/LICENSE.xray
FROM scratch
COPY --from=build /out/xray /usr/local/bin/xray
COPY --from=build /out/LICENSE.xray /usr/share/licenses/xray/LICENSE
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/xray"]
