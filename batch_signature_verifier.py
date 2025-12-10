import json
import argparse
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address, keccak
from eth_account import Account


def parse_args():
    parser = argparse.ArgumentParser(
        description='Verify signatures from JSON file'
    )
    parser.add_argument('--json-file', type=str, required=True,
                        help='Path to JSON file with signatures')
    parser.add_argument('--signer', type=str, required=True,
                        help='Expected signer address (to verify against)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print detailed verification results for each address')
    return parser.parse_args()


def from_fixed_32bytes_hex(hex_str: str) -> int:
    """Convert 32-byte hex string back to integer."""
    return int(hex_str, 16)


def verify_signature(chainid, contract, account_address, r, s, v, expected_signer):
    """
    Verify a signature matches the expected format and signer.
    
    This matches the Solidity verification:
    bytes32 digest = keccak256(abi.encode(block.chainid, address(this), account));
    require(ECDSA.recover(digest, v, r, s) == signer, InvalidSignature());
    """
    try:
        # Encode the data: [chainid, contract, account] - matches Solidity abi.encode
        encoded = abi_encode(
            ["uint256", "address", "address"],
            [chainid, to_checksum_address(contract), to_checksum_address(account_address)]
        )

        # Hash with keccak256 - matches Solidity keccak256(abi.encode(...))
        msg_hash = keccak(encoded)

        # check size r and s
        if len(r) != 66 or len(s) != 66:
            raise ValueError("R and S must be 32 bytes")

        # Convert r, s from hex strings to integers
        r_int = from_fixed_32bytes_hex(r)
        s_int = from_fixed_32bytes_hex(s)

        # Recover the signer from the signature
        recovered_signer = Account._recover_hash(
            msg_hash,
            vrs=(v, r_int, s_int)
        )

        # Compare with expected signer (case-insensitive)
        is_valid = recovered_signer.lower() == expected_signer.lower()
        
        return is_valid, recovered_signer
    except Exception as e:
        return False, None


def verify_batch(json_file, expected_signer, verbose=False):
    """Verify all signatures in the JSON file."""
    print(f"Reading signatures from {json_file}...")
    with open(json_file, 'r') as f:
        data = json.load(f)

    chainid = data.get('chainid')
    contract = data.get('contract')
    signatures = data.get('signatures', {})
    owners = data.get('owners', {})

    if not chainid or not contract:
        raise ValueError("JSON file must contain 'chainid' and 'contract' fields")

    print(f"Chain ID: {chainid}")
    print(f"Contract: {contract}")
    print(f"Expected signer: {expected_signer}")
    print(f"Total signatures to verify: {len(signatures)}\n")

    results = {
        'valid': [],
        'invalid': [],
        'missing': []
    }

    # Verify each signature
    for account_address, sig in signatures.items():
        r = sig.get('r')
        s = sig.get('s')
        v = sig.get('v')

        if not all([r, s, v is not None]):
            results['missing'].append(account_address)
            if verbose:
                print(f"❌ {account_address}: Missing signature components")
            continue

        is_valid, recovered_signer = verify_signature(
            chainid, contract, account_address, r, s, v, expected_signer
        )

        if is_valid:
            results['valid'].append(account_address)
            if verbose:
                print(f"✅ {account_address}: Valid signature (recovered: {recovered_signer.lower()})")
        else:
            results['invalid'].append({
                'address': account_address,
                'recovered': recovered_signer.lower() if recovered_signer else None
            })
            if verbose:
                recovered_str = recovered_signer.lower() if recovered_signer else "Failed to recover"
                print(f"❌ {account_address}: Invalid signature (recovered: {recovered_str}, expected: {expected_signer.lower()})")

    # Summary
    print(f"\n{'='*60}")
    print(f"Verification Summary:")
    print(f"  ✅ Valid:   {len(results['valid'])}")
    print(f"  ❌ Invalid: {len(results['invalid'])}")
    print(f"  ⚠️  Missing: {len(results['missing'])}")
    print(f"{'='*60}")

    # Check if all addresses in owners have signatures
    if owners:
        owner_addresses = set(addr.lower() for addr in owners.values())
        signature_addresses = set(addr.lower() for addr in signatures.keys())
        missing_in_signatures = owner_addresses - signature_addresses
        
        if missing_in_signatures:
            print(f"\n⚠️  Warning: {len(missing_in_signatures)} owner addresses don't have signatures")
            if verbose:
                for addr in sorted(missing_in_signatures):
                    print(f"    - {addr}")

    # Return success if all signatures are valid
    all_valid = len(results['invalid']) == 0 and len(results['missing']) == 0
    return all_valid, results


def main():
    args = parse_args()
    expected_signer = to_checksum_address(args.signer)

    try:
        all_valid, results = verify_batch(args.json_file, expected_signer, args.verbose)
        
        if all_valid:
            print("\n✅ All signatures are valid!")
            exit(0)
        else:
            print("\n❌ Some signatures are invalid or missing!")
            exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()

