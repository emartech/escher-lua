.PHONY: build test

build:
	docker compose build

test:
	docker compose run --rm app busted spec
