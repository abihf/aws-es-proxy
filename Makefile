TAG=aws-es-proxy

release:
	docker build -t ${TAG} .
	docker push emanekat/aws-es-proxy:${TAG}