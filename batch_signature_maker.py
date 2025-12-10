import json
import argparse
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address, keccak
from eth_account import Account

def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate signatures for addresses from ownerOf JSON file'
    )
    parser.add_argument('--chainid', type=int, required=True, help='Chain ID')
    parser.add_argument('--contract', type=str, required=True, help='Contract address')
    parser.add_argument('--json-file', type=str, required=True, help='Path to JSON file with owners')
    parser.add_argument('--private-key', type=str, required=True, help='Private key for signing')
    parser.add_argument('--output', type=str, default='signatures.json',
                        help='Output JSON file (default: signatures.json)')
    return parser.parse_args()


def load_owners(json_file):
    print(f"Reading owners from {json_file}...")
    with open(json_file, 'r') as f:
        data = json.load(f)

    owners = data.get('owners', {})
    # Convert owners to lowercase for output
    owners = {k: v.lower() for k, v in owners.items()}
    # Keep checksummed for signing process
    unique_addresses = {to_checksum_address(addr) for addr in owners.values()}
    print(f"Found {len(unique_addresses)} unique addresses")
    return data, owners, unique_addresses


def to_fixed_32bytes_hex(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def sign_for_address(chainid, contract, account_address, private_key):
    """
    Returns a dict with r, s, v for a single address, or raises on error.
    
    This matches the Solidity verification:
    bytes32 digest = keccak256(abi.encode(block.chainid, address(this), account));
    require(ECDSA.recover(digest, v, r, s) == signer, InvalidSignature());
    """
    # Encode the data: [chainid, contract, account] - matches Solidity abi.encode
    encoded = abi_encode(
        ["uint256", "address", "address"],
        [chainid, contract, account_address]
    )

    # Hash with keccak256 - matches Solidity keccak256(abi.encode(...))
    msg_hash = keccak(encoded)

    # Sign the raw hash directly using Account._sign_hash (not EIP-191 wrapped)
    signed = Account._sign_hash(msg_hash, private_key=private_key)

    # Return in JSON-friendly format
    return {
        "r": to_fixed_32bytes_hex(signed.r),
        "s": to_fixed_32bytes_hex(signed.s),
        "v": signed.v,
        # "signature": signed.signature.hex(),  # if you want full sig
    }


def generate_signatures(chainid, contract, unique_addresses, private_key):
    signatures = {}
    print(f"Generating signatures for chainid={chainid}, contract={contract}...")
    for account_address in unique_addresses:
        try:
            sig = sign_for_address(chainid, contract, account_address, private_key)
            # Store with lowercase key for output
            signatures[account_address.lower()] = sig
            print(f"Signed for {account_address.lower()}")
        except Exception as e:
            print(f"Error signing for {account_address}: {str(e)}")
            continue
    return signatures


def save_output(output_file, chainid, contract, data, owners, signatures):
    output_data = {
        "chainid": chainid,
        "contract": contract.lower(),
        "block": data.get('block'),
        "owners": owners,
        "signatures": signatures
    }

    print(f"\nSaving signatures to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"Successfully generated {len(signatures)} signatures")
    print(f"Results saved to {output_file}")

def main():
    args = parse_args()

    chainid = args.chainid
    contract = to_checksum_address(args.contract)
    private_key = args.private_key
    json_file = args.json_file
    output_file = args.output

    data, owners, unique_addresses = load_owners(json_file)
    signatures = generate_signatures(chainid, contract, unique_addresses, private_key)
    save_output(output_file, chainid, contract, data, owners, signatures)


if __name__ == "__main__":
    main()

#python signature_script2.py --chainid 1 --contract 0xF478F017cfe92AaF83b2963A073FaBf5A5cD0244 --json-file ownerof_results_block_23929260.json --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --output mainnet.json

#python signature_script2.py --chainid 11155111 --contract 0xF7f7996ce30179CDe83699417D49F405d742c0F1 --json-file ownerof_results_block_9789801.json --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --output testnet.json
