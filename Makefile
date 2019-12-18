clean:
	rm -f dist/flanneld*

flanneld: $(shell find . -type f  -name '*.go')
	go build -o dist/flanneld -ldflags '-s -w -extldflags "-static"'

