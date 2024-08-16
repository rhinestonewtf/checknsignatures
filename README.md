# CheckNSignatures

**A library to verify multiple signatures**

## Using the library

In a contract, you can use the `CheckNSignatures` library to verify multiple signatures:

```solidity
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";

contract Example {
    using CheckSignatures for bytes32;

   function verify(bytes32 hash, bytes memory signatures) external view returns (bool) {
        // Determine the number of required signatures
        uint256 requiredSignatures = 2;

        // Recover the signers
        address[] memory recoveredSigners = hash.recoverNSignatures(signatures, requiredSignatures);

        // Check if the signers are the expected ones
        // ...
    }
}
```

## Using this repo

To install the dependencies, run:

```bash
forge install
```

To build the project, run:

```bash
forge build
```

To run the tests, run:

```bash
forge test
```

## Contributing

For feature or change requests, feel free to open a PR, start a discussion or get in touch with us.

## Credits

- [Safe](https://github.com/safe-global/safe-smart-account) and [Richard](https://github.com/rmeissner): For the initial implementation in the Safe Smart Account
