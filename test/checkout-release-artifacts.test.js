import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { posix } from "node:path";
import test from "node:test";
import ts from "typescript";

import {
  CHECKOUT_RELEASE_ARTIFACTS,
  CHECKOUT_RELEASE_EXECUTION_FILES,
} from "../src/checkout-release-artifacts.js";

const RELEASE_METADATA_FILE = "src/checkout-release-artifacts.js";
const RELEASE_RUNTIME_ROOT = "src/hosted-audit.js";

test("hosted release artifact digests bind the declared transitive execution stack and behavior variant", async () => {
  let source = "";
  for (const path of CHECKOUT_RELEASE_EXECUTION_FILES) {
    source += `${path}\0${await readFile(path, "utf8")}\0`;
  }

  for (const variant of ["vulnerable", "fixed"]) {
    const expected = createHash("sha256")
      .update(`arena.checkout.owned-execution-stack.v1\0${variant}\0${source}`)
      .digest("base64url");
    assert.equal(CHECKOUT_RELEASE_ARTIFACTS[variant].digest, expected);
    assert.equal(CHECKOUT_RELEASE_ARTIFACTS[variant].subject, `arena.checkout.owned-execution-stack:${variant}`);
  }
  assert.notEqual(CHECKOUT_RELEASE_ARTIFACTS.vulnerable.digest, CHECKOUT_RELEASE_ARTIFACTS.fixed.digest);
});

test("the declared release execution manifest exactly closes over local runtime imports", async () => {
  const declared = new Set(CHECKOUT_RELEASE_EXECUTION_FILES);
  assert.equal(declared.size, CHECKOUT_RELEASE_EXECUTION_FILES.length, "execution manifest must not contain duplicates");
  assert.deepEqual(CHECKOUT_RELEASE_EXECUTION_FILES, [...CHECKOUT_RELEASE_EXECUTION_FILES].sort(), "execution manifest must be canonical");

  const allowed = new Set([...declared, RELEASE_METADATA_FILE]);
  const reachable = new Set();
  const pending = [RELEASE_RUNTIME_ROOT];
  while (pending.length) {
    const importer = pending.pop();
    if (reachable.has(importer)) continue;
    reachable.add(importer);
    for (const dependency of await localModuleDependencies(importer)) {
      assert.equal(
        allowed.has(dependency),
        true,
        `${importer} imports ${dependency}, which is outside the committed release execution manifest`,
      );
      pending.push(dependency);
    }
  }

  assert.deepEqual(
    [...reachable].sort(),
    [...allowed].sort(),
    "every committed execution file must be reachable from the hosted release runtime root",
  );
});

async function localModuleDependencies(importer) {
  const source = await readFile(importer, "utf8");
  const sourceFile = ts.createSourceFile(importer, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const dependencies = [];

  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      add(node.moduleSpecifier);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      if (node.arguments.length !== 1 || !ts.isStringLiteral(node.arguments[0])) {
        assert.fail(`${importer} contains a non-literal dynamic import that cannot be committed statically`);
      }
      add(node.arguments[0]);
    }
    ts.forEachChild(node, visit);
  }

  function add(specifierNode) {
    if (!ts.isStringLiteral(specifierNode) || !specifierNode.text.startsWith(".")) return;
    dependencies.push(posix.normalize(posix.join(posix.dirname(importer), specifierNode.text)));
  }

  visit(sourceFile);
  return [...new Set(dependencies)].sort();
}
