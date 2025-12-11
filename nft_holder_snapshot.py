import json
import argparse
from web3 import Web3
from eth_utils import to_checksum_address
import sys

# Contract addresses by network
CONTRACT_ADDRESSES = {
    "testnet": "0xF7f7996ce30179CDe83699417D49F405d742c0F1",
    "mainnet": "0xF478F017cfe92AaF83b2963A073FaBf5A5cD0244"
}

# Max token IDs
MAX_TOKEN_IDS = {
    "testnet": 128,
    "mainnet": 1024
}

# ABI for ownerOf
ownerOf_abi = {
    "constant": True,
    "inputs": [{"name": "tokenId", "type": "uint256"}],
    "name": "ownerOf",
    "outputs": [{"name": "", "type": "address"}],
    "payable": False,
    "stateMutability": "view",
    "type": "function"
}
contract_abi = [ownerOf_abi]

def parse_args():
    parser = argparse.ArgumentParser(description='Query ownerOf for tokenIds at a specific block')
    parser.add_argument('--block', type=int, required=True)
    parser.add_argument('--network', type=str, default='mainnet', choices=['testnet', 'mainnet'])
    parser.add_argument('--rpc', type=str, default='https://eth.llamarpc.com')
    parser.add_argument('--test-rpcs', type=str, default='https://ethereum-rpc.publicnode.com https://gateway.tenderly.co/public/mainnet')
    parser.add_argument('--test-mode', action='store_true', default=False)
    return parser.parse_args()


def init_web3(rpc_url):
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise Exception(f"Could not connect to RPC endpoint: {rpc_url}")
    return w3


def get_contract(w3, network):
    address = to_checksum_address(CONTRACT_ADDRESSES[network])
    max_id = MAX_TOKEN_IDS[network]
    contract = w3.eth.contract(address=address, abi=contract_abi)
    return contract, address.lower(), max_id


def fetch_owner(contract, token_id, block_number):
    """Single ownerOf call wrapped in try/except."""
    try:
        owner = contract.functions.ownerOf(token_id).call(block_identifier=block_number)
        if owner and owner != "0x0000000000000000000000000000000000000000":
            return owner.lower()
    except Exception:
        return None
    return None


def scan_tokens(contract, max_token_id, block_number):
    owners = {}
    for token_id in range(1, max_token_id + 1):
        owner = fetch_owner(contract, token_id, block_number)
        if owner:
            owners[str(token_id)] = owner
            print(f"TokenId {token_id}: {owner}")
        else:
            print(f"TokenId {token_id}: not found / error")
    return owners


def save_results(block, owners):
    filename = f"ownerof_results_block_{block}.json"
    with open(filename, "w") as f:
        json.dump({"block": block, "owners": owners}, f, indent=2)
    return filename

def perform_test(block, network, test_rpcs):
    rpcs = test_rpcs.split(" ")
    print(f"Performing test with {len(rpcs)} RPCs")
    
    if len(rpcs) < 2:
        print("Need at least 2 RPCs to perform test")
        return 1
    
    data = []
    max_token_id = 0
    for i, rpc in enumerate(rpcs):
        w3 = init_web3(rpc)
        contract, _, max_token_id = get_contract(w3, network)
        data.append({"w3": w3, "contract": contract})

    for i in range(1, max_token_id + 1):
        owner = fetch_owner(data[0]["contract"], i, block)
        for j in range(1, len(rpcs)):
            owner_j = fetch_owner(data[j]["contract"], i, block)
            if owner != owner_j:
                print(f"TokenId {i}: owner mismatch between RPCs {0} and {j}")
                print(f"RPC {0} owner: {owner}")
                print(f"RPC {j} owner: {owner_j}")
                return 1
        print(f"TokenId {i}: owner matched between all RPCs")
    return 0

def main():
    args = parse_args()
    block = args.block
    network = args.network.lower()
    
    if args.test_mode:
        print("Running in test mode")
        return perform_test(block, network, args.test_rpcs)

    w3 = init_web3(args.rpc)
    contract, address, max_token_id = get_contract(w3, network)

    print(f"Scanning token IDs 1..{max_token_id} at block {block} on {network}")
    print(f"Contract: {address}")

    owners = scan_tokens(contract, max_token_id, block)
    output_file = save_results(block, owners)

    print(f"\nSaved results to {output_file}")
    print(f"Total tokens found: {len(owners)}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
