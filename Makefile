.PHONY: setup setup_dep setup_test setup_mobile setup_linter deps install test fmt lint android proto clean clean_deps run

ALL = ./...

# All .go files not in vendor directory
ALL_GO := $(shell find . -type f -name '*.go' -not -path "./vendor/*")

all: install

# Setup and update all the required tools
setup: setup_dep setup_test setup_linter setup_mobile

setup_dep:
	go get -u github.com/golang/dep/cmd/dep

setup_test:
	go get -u github.com/stretchr/testify/assert

setup_mobile:
	go get -u golang.org/x/mobile/cmd/gomobile
	gomobile init

setup_linter:
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install --update

# Runs dep ensure to populate the vendor directory with
# the required dependencies and potentially modify Gopkg.lock.
deps:
	dep ensure -v

# Install go package to produce emmy binaries
install:
	go install

# Install to produce emmy binary, but also add version information
# Use with "make release version=x.y.z"
release:
	go install -ldflags "-X main.version=$(version)" emmy.go

# Run test for all packages and report test coverage status
test:
	go test -v -cover $(ALL)

# Lists and formats all go source files with goimports
fmt:
	# List of files with different formatting than goimports'
	@goimports -l $(ALL_GO)
	@goimports -w $(ALL_GO)

# Displays output from several linters
# Auto-generated code for protobuffers is excluded from this check
lint:
	-gometalinter --exclude=.*.pb.go \
	 	--enable=gofmt \
		--enable=goimports \
		--enable=gosimple \
		--enable=misspell \
		--vendor \
		$(ALL)

# Generates Android archive (AAR) for emmy's client compatibility package
android:
	gomobile bind -v -o emmy.aar github.com/xlab-si/emmy/client/compatibility

# Generates protobuffer code based on protobuffer definitions
# Requires protoc compiler
proto:
	protoc -I proto/ \
 	 	proto/messages.proto \
 	 	proto/services.proto \
 	 	--go_out=plugins=grpc:proto

# Removes temporary files produced by the targets
clean:
	-rm emmy.aar emmy-sources.jar

clean_deps:
	-rm -rf vendor

# Rebuilds emmy server and starts emmy server and redis instance
run:
	docker-compose up --build
