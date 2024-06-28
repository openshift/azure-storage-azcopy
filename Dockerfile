FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.20 AS builder
WORKDIR /go/src/github.com/openshift/azure-storage-azcopy
COPY . .
RUN go build -o ./bin/azcopy .

FROM registry.ci.openshift.org/ocp/4.20:base-rhel9
COPY --from=builder /go/src/github.com/openshift/azure-storage-azcopy/bin/azcopy /usr/bin/
