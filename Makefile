TAG=emanekat/aws-es-proxy:aws-es-proxy

release:
	docker build -t ${TAG} .
	docker push ${TAG}
