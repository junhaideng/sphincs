.PHYON: test

test: signature common hash merkle
	go test -v ./... -count=1

colc:
	cloc . --not-match-f=".*_test.go"

