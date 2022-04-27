echo "wots+"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkWOTSPlus -benchtime=10000x -benchmem -count=1 -timeout=24h

echo "horst"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkHorst -benchtime=10000x -benchmem -count=1 -timeout=24h

echo "sphincs"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkSphincs -benchtime=10000x -benchmem -count=1 -timeout=24h