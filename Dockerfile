FROM alpine:3.7

ENV TERRAFORM_VERSION 0.12.9
ENV TERRAFORM_PROVIDER_OPENSTACK_VERSION 1.23.0

ENV OS_DELAYED_AUTH true

RUN apk add --no-cache ca-certificates
ADD https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip /bin/
ADD https://releases.hashicorp.com/terraform-provider-openstack/${TERRAFORM_PROVIDER_OPENSTACK_VERSION}/terraform-provider-openstack_${TERRAFORM_PROVIDER_OPENSTACK_VERSION}_linux_amd64.zip /root/.terraform.d/plugins/
RUN for k in /bin/ /root/.terraform.d/plugins/; do for i in $k*.zip; do unzip -qd $k $i; done && rm $k*.zip && chmod +x $k*; done
ADD bin/terraform-ingress-controller /bin/

CMD ["/bin/terraform-ingress-controller"]
