.PHONY: setup setup_test setup_mobile setup_linter install test fmt lint android proto clean run

ALL=./...

all: install

# Setup and update all the required tools
setup: setup_test setup_linter setup_mobile

setup_test:
	go get -u github.com/stretchr/testify/assert

setup_mobile:
	go get -u golang.org/x/mobile/cmd/gomobile

setup_linter:
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install --update

# Install go package to produce emmy binaries
install:
	go install

# Run test for all packages and report test coverage status
test:
	go test -v -cover $(ALL)

# Lists and formats all go source files with goimports
fmt:
	# List of files with different formatting than goimport's
	goimports -l .
	goimports -w .

# Displays output from several linters
# Auto-generated code for protobuffers is excluded from this check
lint:
	-gometalinter --exclude=.*.pb.go \
	 	--enable=gofmt \
		--enable=goimports \
		--enable=gosimple \
		--enable=misspell \
		$(ALL)

# Generates Android archive (AAR) for emmy's client compatibility package
android:
	gomobile bind -v -o emmy.aar github.com/xlab-si/emmy/client/compatibility

# Generates protobuffer code based on protobuffer definitions
# Requires protoc compiler
proto:
	protoc -I protobuf/ \
 	 	protobuf/messages.proto \
 	 	protobuf/services.proto \
 	 	protobuf/enums.proto \
 	 	--go_out=plugins=grpc:protobuf

# Removes temporary files produced by the targets
clean:
	-rm emmy.aar emmy-sources.jar

run:
	docker-compose up --build
