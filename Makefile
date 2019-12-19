TAG="v0.0.1-wyp"

clean:
	rm -f dist/flanneld*

flanneld: $(shell find . -type f  -name '*.go')
	go build -o dist/flanneld -ldflags '-s -w -X github.com/coreos/flannel/version.Version=$(TAG) -extldflags "-static"'

