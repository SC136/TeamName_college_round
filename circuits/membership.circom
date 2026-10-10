pragma circom 2.0.0;

/**
 * Incognito: Anonymous Membership & Unlinkable Submission ZK Circuit
 *
 * Proves that:
 * 1. The prover knows private (identityNullifier, identityTrapdoor) generating a valid commitment.
 * 2. The commitment exists in the Merkle Tree with public root `merkleRoot`.
 * 3. The public `nullifierHash` is correctly derived from `identityNullifier` and `topicId`.
 * 4. The proof is cryptographically bound to `reportHash`.
 */

include "../node_modules/circomlib/circuits/poseidon.circom";

template MerkleTreeInclusionProof(nLevels) {
    signal input leaf;
    signal input pathElements[nLevels];
    signal input pathIndices[nLevels];
    signal output root;

    signal current[nLevels + 1];
    current[0] <== leaf;

    component hashers[nLevels];

    for (var i = 0; i < nLevels; i++) {
        hashers[i] = Poseidon(2);

        // If pathIndices[i] == 0: left = current[i], right = pathElements[i]
        // If pathIndices[i] == 1: left = pathElements[i], right = current[i]
        signal left;
        signal right;

        left <== current[i] + pathIndices[i] * (pathElements[i] - current[i]);
        right <== pathElements[i] + pathIndices[i] * (current[i] - pathElements[i]);

        hashers[i].inputs[0] <== left;
        hashers[i].inputs[1] <== right;

        current[i + 1] <== hashers[i].out;
    }

    root <== current[nLevels];
}

template AnonymousMembershipProof(nLevels) {
    // --- Private Witness ---
    signal input identityNullifier;
    signal input identityTrapdoor;
    signal input treeSiblings[nLevels];
    signal input treePathIndices[nLevels];

    // --- Public Inputs ---
    signal input merkleRoot;
    signal input topicId;
    signal input reportHash;
    signal input slotIndex;
    signal input nullifierHash;

    // --- 1. Identity Commitment Computation ---
    // secret = Poseidon(nullifier, trapdoor)
    component secretHasher = Poseidon(2);
    secretHasher.inputs[0] <== identityNullifier;
    secretHasher.inputs[1] <== identityTrapdoor;

    // commitment = Poseidon(secret)
    component commitmentHasher = Poseidon(1);
    commitmentHasher.inputs[0] <== secretHasher.out;

    // --- 2. Merkle Tree Membership Verification ---
    component merkleVerifier = MerkleTreeInclusionProof(nLevels);
    merkleVerifier.leaf <== commitmentHasher.out;
    for (var i = 0; i < nLevels; i++) {
        merkleVerifier.pathElements[i] <== treeSiblings[i];
        merkleVerifier.pathIndices[i] <== treePathIndices[i];
    }

    // Constraint: Computed root must equal public Merkle root
    merkleVerifier.root === merkleRoot;

    // --- 3. Topic Nullifier Derivation ---
    // nullifier = Poseidon(identityNullifier, topicId, slotIndex)
    component nullifierDerivation = Poseidon(3);
    nullifierDerivation.inputs[0] <== identityNullifier;
    nullifierDerivation.inputs[1] <== topicId;
    nullifierDerivation.inputs[2] <== slotIndex;

    // Constraint: Computed nullifier must match public nullifierHash
    nullifierDerivation.out === nullifierHash;

    // --- 4. Report Hash Cryptographic Binding ---
    // Bind reportHash to proof execution to prevent front-running
    signal dummyBinding;
    dummyBinding <== reportHash * reportHash;
}

component main {public [merkleRoot, topicId, reportHash, slotIndex, nullifierHash]} = AnonymousMembershipProof(16);
