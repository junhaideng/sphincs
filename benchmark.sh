echo "wots+"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkWOTSPlus -benchtime=1000x -benchmem -count=1 -timeout=24h -cpu 1 

echo "horst"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkHorst -benchtime=1000x -benchmem -count=1 -timeout=24h -cpu 1 

echo "sphincs"
go test github.com/junhaideng/sphincs/signature -bench BenchmarkSphincs -benchtime=1000x -benchmem -count=1 -timeout=24h -cpu 1 

echo "hash"
go test github.com/junhaideng/sphincs/merkle -bench ^BenchmarkTreeHashAndChainHash$ -benchtime=10000x -benchmem -count=1 -timeout=24h -cpu 1  