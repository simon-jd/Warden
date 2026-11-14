FROM scratch
COPY --chmod=0555 warden-probe /warden-probe
COPY --chmod=0666 write-probe /write-probe
USER 65534:65534
ENTRYPOINT ["/warden-probe"]
