import { sha256 } from "fuels";

// Generic type for any Input type (enums, structs, primitives)
type InputType = any;

/**
 * Generic function to encode any Input type as bytes
 * Uses the convention that enum variants start with uppercase letters
 */
export function encodeInputAsBytes(input: InputType): Uint8Array {
  // Handle null/undefined
  if (input === null || input === undefined) {
    return new Uint8Array(0);
  }

  // Handle primitive types
  if (typeof input === "string") {
    // Check if it's a hex string (b256)
    if (input.startsWith("0x") && input.length === 66) {
      // b256 - 32 bytes
      const hexStr = input.slice(2);
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
      }
      return bytes;
    } else {
      // Regular string - encode as UTF-8 bytes (no length prefix)
      return new TextEncoder().encode(input);
    }
  }

  if (typeof input === "number" || typeof input === "bigint") {
    // Encode as u64 (8 bytes, big-endian)
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setBigUint64(0, BigInt(input.toString()), false);
    return new Uint8Array(buffer);
  }

  if (typeof input === "boolean") {
    // Encode as single byte
    return new Uint8Array([input ? 1 : 0]);
  }

  // Handle BN (BigNumber) objects from Fuel
  if (
    input &&
    typeof input === "object" &&
    typeof input.toString === "function"
  ) {
    const str = input.toString();
    if (/^\d+$/.test(str)) {
      // It's a numeric string, treat as u64
      const buffer = new ArrayBuffer(8);
      const view = new DataView(buffer);
      view.setBigUint64(0, BigInt(str), false);
      return new Uint8Array(buffer);
    }
  }

  // Handle arrays/vectors (including Vec<T> objects)
  if (Array.isArray(input)) {
    // Encode each element and concatenate (no length prefix)
    const elementBytes = input.map((item) => encodeInputAsBytes(item));
    const totalSize = elementBytes.reduce(
      (sum, bytes) => sum + bytes.length,
      0
    );

    const result = new Uint8Array(totalSize);
    let offset = 0;
    for (const bytes of elementBytes) {
      result.set(bytes, offset);
      offset += bytes.length;
    }
    return result;
  }

  // Handle Vec<T> objects (Fuel's Vec type)
  if (input && typeof input === "object" && Array.isArray(input.elements)) {
    // This is a Vec<T> object with an elements array
    return encodeInputAsBytes(input.elements);
  }

  // Handle objects (enums and structs)
  if (typeof input === "object" && input !== null) {
    const keys = Object.keys(input);

    // Check if it's an enum by looking for uppercase-starting keys
    const enumKeys = keys.filter((key) => /^[A-Z]/.test(key));

    if (enumKeys.length === 1 && keys.length === 1) {
      // This is an enum with a single variant
      const variantName = enumKeys[0];
      const variantValue = input[variantName];

      // Get discriminant based on common enum variant names
      const discriminant = getEnumDiscriminant(variantName);
      const discriminantByte = new Uint8Array([discriminant]);
      const valueBytes = encodeInputAsBytes(variantValue);

      const result = new Uint8Array(
        discriminantByte.length + valueBytes.length
      );
      result.set(discriminantByte, 0);
      result.set(valueBytes, discriminantByte.length);
      return result;
    }

    // Handle as struct - concatenate all field values in original order (not sorted)
    const fieldBytes: Uint8Array[] = [];
    for (const key of keys) {
      fieldBytes.push(encodeInputAsBytes(input[key]));
    }

    const totalSize = fieldBytes.reduce((sum, bytes) => sum + bytes.length, 0);
    const result = new Uint8Array(totalSize);
    let offset = 0;
    for (const bytes of fieldBytes) {
      result.set(bytes, offset);
      offset += bytes.length;
    }
    return result;
  }

  throw new Error(`Cannot encode input of type: ${typeof input}`);
}

/**
 * Helper function to get enum discriminant from variant name
 * Maps common enum variants to their expected indices
 */
function getEnumDiscriminant(variantName: string): number {
  // Common mappings for known enum variants
  const knownVariants: { [key: string]: number } = {
    Activate: 0,
    SendFleet: 1,
    Eventual: 0,
    Known: 1,
    Address: 0,
    ContractId: 1,
    // Add more as needed
  };

  if (variantName in knownVariants) {
    return knownVariants[variantName];
  }

  // Fallback: simple hash for unknown variants
  let hash = 0;
  for (let i = 0; i < variantName.length; i++) {
    const char = variantName.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash) % 256;
}

/**
 * Generic encoder that takes variable arguments and concatenates their byte encodings
 * Useful for creating hash inputs from multiple data pieces
 */
export function encodeMultipleInputs(...args: InputType[]): Uint8Array {
  // Encode each argument
  const argBytes = args.map((arg) => encodeInputAsBytes(arg));

  // Calculate total size
  const totalSize = argBytes.reduce((sum, bytes) => sum + bytes.length, 0);

  // Combine all bytes
  const result = new Uint8Array(totalSize);
  let offset = 0;

  // Copy argument bytes in order
  for (const bytes of argBytes) {
    result.set(bytes, offset);
    offset += bytes.length;
  }

  return result;
}

/**
 * Hasher class for incrementally building up hash inputs
 * Provides a convenient API similar to crypto hashers
 */
export class Hasher {
  private buffer: Uint8Array[];

  constructor() {
    this.buffer = [];
  }

  /**
   * Add input data to the hasher
   * @param input Any input type that can be encoded
   * @returns this (for method chaining)
   */
  update(input: InputType): this {
    const bytes = encodeInputAsBytes(input);
    this.buffer.push(bytes);
    return this;
  }

  /**
   * Compute the final hash of all accumulated data
   * @returns The SHA-256 hash as a hex string
   */
  digest(): string {
    // Calculate total size
    const totalSize = this.buffer.reduce((sum, bytes) => sum + bytes.length, 0);

    // Combine all bytes
    const combined = new Uint8Array(totalSize);
    let offset = 0;
    for (const bytes of this.buffer) {
      combined.set(bytes, offset);
      offset += bytes.length;
    }

    // Compute hash
    return sha256(combined);
  }

  /**
   * Get the raw bytes without hashing
   * @returns The concatenated bytes
   */
  getBytes(): Uint8Array {
    // Calculate total size
    const totalSize = this.buffer.reduce((sum, bytes) => sum + bytes.length, 0);

    // Combine all bytes
    const combined = new Uint8Array(totalSize);
    let offset = 0;
    for (const bytes of this.buffer) {
      combined.set(bytes, offset);
      offset += bytes.length;
    }

    return combined;
  }

  /**
   * Reset the hasher to start fresh
   * @returns this (for method chaining)
   */
  reset(): this {
    this.buffer = [];
    return this;
  }

  /**
   * Create a new hasher with the same accumulated data
   * @returns A new Hasher instance with copied data
   */
  clone(): Hasher {
    const newHasher = new Hasher();
    newHasher.buffer = [...this.buffer];
    return newHasher;
  }
}
