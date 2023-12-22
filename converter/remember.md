~~~
python3 fuzzer/main.py -a examples/test/Ballot.json -c 0xBC9129Dc0487fc2E169941C75aABC539f208fb01 --solc v0.8.21 --evm byzantium -g 1000 --rpc-host 127.0.0.1 --rpc-port 8545 --max-symbolic-execution 50 --max-individual-length 20 -pm 0.3
