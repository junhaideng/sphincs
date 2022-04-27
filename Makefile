.PHYON: test

test: signature common hash merkle
	go test -v ./... -count=1

bench: 
	bash benchmark.sh

colc:
	cloc . --not-match-f=".*_test.go"

colc-all:
	cloc .
