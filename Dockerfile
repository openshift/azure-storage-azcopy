FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.23-openshift-4.19 AS builder
WORKDIR /go/src/github.com/openshift/azure-storage-azcopy
COPY . .
RUN go build -o ./bin/azcopy .

FROM registry.ci.openshift.org/ocp/4.19:base-rhel9
COPY --from=builder /go/src/github.com/openshift/azure-storage-azcopy/bin/azcopy /usr/bin/
