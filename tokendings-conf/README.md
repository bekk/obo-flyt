## Local cluster

1. Follow the instructions to setup Skiperator [here](https://github.com/kartverket/skiperator/blob/main/CONTRIBUTING.md), i.e., clone repository local setup with make. Also, add the following to the Skiperator dependencies in the Makefile and add the install-jwker-crds to the setup-local.

```
.PHONY: setup-local
setup-local: kind-cluster install-istio install-cert-manager install-prometheus-crds install-digdirator-crds install-skiperator install-jwker-crds
	@echo "Cluster $(SKIPERATOR_CONTEXT) is setup"
```

```
#### SKIPERATOR DEPENDENCIES ####
.PHONY: install-jwker-crds
install-jwker-crds:
	@echo "Installing jwker crds"
	@kubectl apply -f https://raw.githubusercontent.com/nais/liberator/main/config/crd/bases/nais.io_jwkers.yaml --context $(SKIPERATOR_CONTEXT)
```

2.  Opprett namespace obo, deretter kan man applye database, tokendings og jwker. Sjekk at tokendings kjører opp. Trolig vil den ikke få tilgang til fake-auth endepunktet pga. nettverkspolicy. Dette løses ved å restarte networkpolicy til tokendings.
