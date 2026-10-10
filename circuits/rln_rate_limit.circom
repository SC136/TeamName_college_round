pragma circom 2.0.0;

/**
 * Incognito: Rate-Limiting Nullifier (RLN) Circuit
 *
 * Implements Shamir's Secret Sharing polynomial evaluation in ZK:
 *   a1 = Poseidon(identitySecret, topicId, epoch)
 *   y = identitySecret + a1 * messageHash
 *   nullifier = Poseidon(a1)
 */

include "../node_modules/circomlib/circuits/poseidon.circom";

template RLNRateLimiter() {
    // Private Witness
    signal input identitySecret;

    // Public Inputs
    signal input topicId;
    signal input epoch;
    signal input messageHash;
    signal input expectedNullifier;
    signal input expectedY;

    // Compute slope a1 = Poseidon(identitySecret, topicId, epoch)
    component slopeHasher = Poseidon(3);
    slopeHasher.inputs[0] <== identitySecret;
    slopeHasher.inputs[1] <== topicId;
    slopeHasher.inputs[2] <== epoch;

    // Verify nullifier = Poseidon(a1)
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== slopeHasher.out;
    nullifierHasher.out === expectedNullifier;

    // Verify polynomial evaluation: y = identitySecret + a1 * messageHash
    signal term;
    term <== slopeHasher.out * messageHash;
    signal computedY;
    computedY <== identitySecret + term;

    computedY === expectedY;
}

component main {public [topicId, epoch, messageHash, expectedNullifier, expectedY]} = RLNRateLimiter();
