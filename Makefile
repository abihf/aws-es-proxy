TAG = abihf/aws-es-proxy:latest

build:
	docker build -t ${TAG} .

release: build
	docker push ${TAG}
