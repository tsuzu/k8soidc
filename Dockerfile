FROM golang:1.18

ADD . /repository
RUN cd /repository && go build -o /bin/k8soidc .

FROM golang:1.18
COPY --from=0 /bin/k8soidc /bin/

CMD [ "/bin/k8soidc" ]
