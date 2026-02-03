# Config
rpc := "http://localhost:8545"
fork_url := "https://1rpc.io/eth"
test_account := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
usdc := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

anvil:
    anvil --fork-url {{fork_url}} --auto-impersonate

setup:
    cd forge && forge script script/Setup.s.sol --rpc-url {{rpc}} --unlocked --broadcast

bal:
    @echo "ETH:"
    @cast balance {{test_account}} --rpc-url {{rpc}}
    @echo "USDC:"
    @cast erc20 balance {{usdc}} {{test_account}} --rpc-url {{rpc}}
