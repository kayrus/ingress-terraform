FROM golang:1.13-alpine as builder

RUN apk add --update git make zip bash gcc musl-dev

WORKDIR /go/src/github.com/terraform-providers/terraform-provider-openstack
RUN git clone https://github.com/terraform-providers/terraform-provider-openstack.git .
RUN make
WORKDIR /go/src/github.com/kayrus/ingress-terraform
RUN git clone https://github.com/kayrus/ingress-terraform.git .
RUN make

FROM alpine:latest

ENV TERRAFORM_VERSION 0.12.9

ENV OS_DELAYED_AUTH true

RUN apk add --no-cache ca-certificates
ADD https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip /bin/
COPY --from=builder /go/bin/terraform-provider-openstack /root/.terraform.d/plugins/terraform-provider-openstack_v1.24.0_x4
COPY --from=builder /go/src/github.com/kayrus/ingress-terraform/bin/terraform-ingress-controller /bin/terraform-ingress-controller
RUN for k in /bin/; do for i in $k*.zip; do unzip -qd $k $i; done && rm $k*.zip && chmod +x $k*; done

CMD ["/bin/terraform-ingress-controller"]
