// This file tells TypeScript about the shape of JavaScript libraries that don't have their own types.
declare module 'shamirs-secret-sharing' {
  export function split(secret: Uint8Array, options: { shares: number; threshold: number }): Uint8Array[];
  export function combine(shares: Uint8Array[]): Uint8Array;
}