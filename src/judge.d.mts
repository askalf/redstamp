import type { Judge, JudgeResult, Tier } from './types.mjs';

export interface MakeJudgeOptions {
  /** Any Anthropic-compatible endpoint. Default `https://api.anthropic.com`. */
  endpoint?: string;
  /** Default `process.env.ANTHROPIC_API_KEY`. */
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
}

/** Build an LLM judge. It fails safe: any error or unparseable reply resolves to null. */
export declare function makeJudge(opts?: MakeJudgeOptions): Judge;

/** Deterministic stub judge for tests: answers from a `tool -> result` map. */
export declare function stubJudge(map?: Record<string, JudgeResult>): Judge;

export type { Judge, JudgeResult, Tier };
