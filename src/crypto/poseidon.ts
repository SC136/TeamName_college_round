/**
 * Incognito Cryptographic Core: Poseidon Hash over BN254 Scalar Field
 *
 * Poseidon is an algebraic zero-knowledge friendly hash function designed
 * specifically for SNARKs (Circom/snarkjs/Groth16).
 * Field modulus: BN254 Fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */

export const SNARK_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function mod(n: bigint, p: bigint = SNARK_FIELD_PRIME): bigint {
  const result = n % p;
  return result >= 0n ? result : result + p;
}

export function modPow(base: bigint, exponent: bigint, p: bigint = SNARK_FIELD_PRIME): bigint {
  let res = 1n;
  let b = mod(base, p);
  let exp = exponent;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      res = mod(res * b, p);
    }
    b = mod(b * b, p);
    exp /= 2n;
  }
  return res;
}

export function modInverse(a: bigint, p: bigint = SNARK_FIELD_PRIME): bigint {
  return modPow(a, p - 2n, p);
}

// Pseudo-random generation of deterministic round constants (Grain-like stream cipher generator)
function generatePoseidonConstants(t: number, totalRounds: number): bigint[] {
  const constants: bigint[] = [];
  let state = 0x1234567890abcdefn;
  for (let i = 0; i < t * totalRounds; i++) {
    state = mod(state * 6364136223846793005n + 1442695040888963407n, SNARK_FIELD_PRIME);
    constants.push(state);
  }
  return constants;
}

// Cauchy / MDS Matrix generation for maximum diffusion
function generateMDSMatrix(t: number): bigint[][] {
  const mds: bigint[][] = [];
  const xs: bigint[] = [];
  const ys: bigint[] = [];
  for (let i = 0; i < t; i++) {
    xs.push(BigInt(i + 1));
    ys.push(BigInt(i + t + 1));
  }
  for (let i = 0; i < t; i++) {
    mds[i] = [];
    for (let j = 0; j < t; j++) {
      const denom = mod(xs[i] - ys[j]);
      mds[i][j] = modInverse(denom);
    }
  }
  return mds;
}

export class Poseidon {
  private t: number; // width = inputs + 1
  private rF: number; // full rounds (8)
  private rP: number; // partial rounds (57 for t=3, 56 for t=2)
  private rounds: number;
  private roundConstants: bigint[];
  private mds: bigint[][];

  constructor(inputsCount: number = 2) {
    this.t = inputsCount + 1;
    this.rF = 8;
    this.rP = this.t === 3 ? 57 : 56;
    this.rounds = this.rF + this.rP;
    this.roundConstants = generatePoseidonConstants(this.t, this.rounds);
    this.mds = generateMDSMatrix(this.t);
  }

  public hash(inputs: bigint[]): bigint {
    if (inputs.length !== this.t - 1) {
      throw new Error(`Poseidon expects ${this.t - 1} inputs, got ${inputs.length}`);
    }

    // Initial state: [capacity=0, inputs...]
    const state: bigint[] = [0n, ...inputs.map((x) => mod(x))];

    const halfF = Math.floor(this.rF / 2);

    let roundConstIdx = 0;

    // 1. First half of Full Rounds
    for (let r = 0; r < halfF; r++) {
      // Add round constants
      for (let i = 0; i < this.t; i++) {
        state[i] = mod(state[i] + this.roundConstants[roundConstIdx++]);
      }
      // S-box x^5 on all state elements
      for (let i = 0; i < this.t; i++) {
        state[i] = modPow(state[i], 5n);
      }
      // MDS matrix multiplication
      this.applyMDS(state);
    }

    // 2. Partial Rounds
    for (let r = 0; r < this.rP; r++) {
      // Add round constants
      for (let i = 0; i < this.t; i++) {
        state[i] = mod(state[i] + this.roundConstants[roundConstIdx++]);
      }
      // S-box x^5 only on the first state element
      state[0] = modPow(state[0], 5n);
      // MDS matrix multiplication
      this.applyMDS(state);
    }

    // 3. Second half of Full Rounds
    for (let r = 0; r < halfF; r++) {
      // Add round constants
      for (let i = 0; i < this.t; i++) {
        state[i] = mod(state[i] + this.roundConstants[roundConstIdx++]);
      }
      // S-box x^5 on all state elements
      for (let i = 0; i < this.t; i++) {
        state[i] = modPow(state[i], 5n);
      }
      // MDS matrix multiplication
      this.applyMDS(state);
    }

    // Result is the first element of state
    return state[0];
  }

  private applyMDS(state: bigint[]): void {
    const nextState = new Array<bigint>(this.t).fill(0n);
    for (let i = 0; i < this.t; i++) {
      let sum = 0n;
      for (let j = 0; j < this.t; j++) {
        sum = mod(sum + this.mds[i][j] * state[j]);
      }
      nextState[i] = sum;
    }
    for (let i = 0; i < this.t; i++) {
      state[i] = nextState[i];
    }
  }
}

// Singletons for 1-to-1, 2-to-1, 3-to-1 and 4-to-1 Poseidon hashing
const poseidon1 = new Poseidon(1);
const poseidon2 = new Poseidon(2);
const poseidon3 = new Poseidon(3);
const poseidon4 = new Poseidon(4);

export function poseidonHash1(a: bigint): bigint {
  return poseidon1.hash([a]);
}

export function poseidonHash2(a: bigint, b: bigint): bigint {
  return poseidon2.hash([a, b]);
}

export function poseidonHash3(a: bigint, b: bigint, c: bigint): bigint {
  return poseidon3.hash([a, b, c]);
}

export function poseidonHash4(a: bigint, b: bigint, c: bigint, d: bigint): bigint {
  return poseidon4.hash([a, b, c, d]);
}

/**
 * Convert arbitrary string to a field element via modular reduction
 */
export function stringToFieldElement(str: string): bigint {
  let hash = 0n;
  for (let i = 0; i < str.length; i++) {
    hash = mod(hash * 31n + BigInt(str.charCodeAt(i)));
  }
  return hash;
}

/**
 * Convert buffer / hex string to a field element
 */
export function hexToFieldElement(hex: string): bigint {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const big = BigInt('0x' + (cleanHex || '0'));
  return mod(big);
}
