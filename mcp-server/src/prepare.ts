#!/usr/bin/env node
import { OperatorManager, initializeOperatorState, readOperatorState, defaultOperatorStatePath } from "./operator.js";
import { RelayError } from "./security.js";
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let path = process.env.RELAY_OPERATOR_STATE ?? defaultOperatorStatePath();
  let initial: string | undefined; let force = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") continue;
    if ((arg === "--state" || arg === "--initialize") && args[i + 1]) { if (arg === "--state") path = args[++i]!; else initial = args[++i]!; }
    else if (arg === "--force") force = true;
    else throw new Error("invalid prepare arguments");
  }
  if (initial) await initializeOperatorState(path, await readOperatorState(initial));
  const state = await readOperatorState(path); await new OperatorManager(path, state.rendezvous_url).prepare({ force });
  process.stdout.write("Package ready. Copy it to the target and run start-relay.cmd.\n");
}
main().catch((error: unknown) => { process.stderr.write(error instanceof RelayError ? error.message + "\n" : "Package export failed. Check the destination, trusted sources, and private operator configuration.\n"); process.exitCode = 1; });
