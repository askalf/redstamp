import type { Action, Policy, Verdict } from './types.mjs';

export interface TaintState {
  calls: number;
  holdsSecret: boolean;
  taintedPaths: string[];
}

/** Stateful checker that catches a secret staged on one call and shipped out on a later one. */
export declare class TaintSession {
  constructor(policy?: Policy);
  policy: Policy | undefined;
  calls: number;
  holdsSecret: boolean;
  taintedPaths: Set<string>;
  /** Check one call in the context of the session so far. Never throws, never lowers a verdict. */
  check(action: Action, skillText?: string): Verdict;
  state(): TaintState;
  /** Clear session state, e.g. at the start of a new agent task. */
  reset(): void;
}

/** Check a sequence of actions through one fresh TaintSession. */
export declare function checkSequence(actions: Action[], policy?: Policy): Verdict[];
