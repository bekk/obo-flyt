## Local Cluster Setup

1. Follow the instructions to set up Skiperator [here](https://github.com/kartverket/skiperator/blob/main/CONTRIBUTING.md). This includes cloning the repository and setting it up locally using `make`. Additionally, add the following to the Skiperator dependencies in the Makefile and include `install-jwker-crds` in the `setup-local` target.

   ```makefile
   .PHONY: setup-local
   setup-local: kind-cluster install-istio install-cert-manager install-prometheus-crds install-digdirator-crds install-skiperator install-jwker-crds
       @echo "Cluster $(SKIPERATOR_CONTEXT) is set up"
   ```

   #### SKIPERATOR DEPENDENCIES

   ```makefile
   .PHONY: install-jwker-crds
   install-jwker-crds:
       @echo "Installing jwker crds"
       @kubectl apply -f https://raw.githubusercontent.com/nais/liberator/main/config/crd/bases/nais.io_jwkers.yaml --context $(SKIPERATOR_CONTEXT)
   ```

2. Ensure that the `obo` namespace is created first. After that, apply the remaining manifests. Verify that `tokendings` can connect to the well-known endpoint for `fake-auth` without timing out. If there are timeouts, it may be due to a misconfigured network policy, which can be resolved by restarting the network policy pod for `tokendings`.

3. Check the logs for `jwker` to confirm that `some-app` and `test-app` are successfully registered as clients.

4. Port-forward the containers for `fake-auth` and `some-app` pods to expose them locally. Access the `fake-auth` service and perform a GET request to `/fake_auth/{aud}`, where `aud` is the client ID of `some-app`, i.e., `kind-skiperator:obo:some-app`.

5. Use the requested token with `some-app` by making a request to `/test/token/{aud}/{token}`, where `aud` is the client ID of `test-app`. The returned token will be an exchanged token.
