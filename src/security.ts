import { readFile } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";
import { finding } from "./findings.js";
import type { Finding, ScanResult } from "./model.js";

const passwordName = /(?:password|passwd|pwd)/i;
const databaseUrl =
  /^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:/\s]+:[^@\s]+@/i;

function extensionKind(file: string): ts.ScriptKind {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (file.endsWith(".js") || file.endsWith(".mjs") || file.endsWith(".cjs"))
    return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

export async function analyzeSecurity(
  root: string,
  files: string[],
  result: ScanResult,
): Promise<void> {
  for (const file of files.filter(
    (candidate) =>
      !candidate.endsWith(".sql") && !candidate.endsWith(".prisma"),
  )) {
    const sourceText = await readFile(file, "utf8");
    const source = ts.createSourceFile(
      file,
      sourceText,
      ts.ScriptTarget.Latest,
      true,
      extensionKind(file),
    );
    const relative = path.relative(root, file).split(path.sep).join("/");
    const createHashImports = new Set<string>();
    const cryptoNamespaces = new Set<string>();

    for (const statement of source.statements) {
      if (
        !ts.isImportDeclaration(statement) ||
        !ts.isStringLiteral(statement.moduleSpecifier) ||
        !["crypto", "node:crypto"].includes(statement.moduleSpecifier.text)
      )
        continue;
      const clause = statement.importClause;
      if (!clause) continue;
      if (clause.name) cryptoNamespaces.add(clause.name.text);
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings))
          cryptoNamespaces.add(clause.namedBindings.name.text);
        else
          for (const element of clause.namedBindings.elements)
            if ((element.propertyName ?? element.name).text === "createHash")
              createHashImports.add(element.name.text);
      }
    }

    const location = (node: ts.Node) => {
      const at = source.getLineAndCharacterOfPosition(node.getStart(source));
      return { file: relative, line: at.line + 1, column: at.character + 1 };
    };

    const add = (
      node: ts.Node,
      ruleId: string,
      title: string,
      severity: Finding["severity"],
      cwe: number,
      evidence: string[],
      recommendation: string,
      identity: string,
    ) => {
      result.findings.push(
        finding(
          {
            ...location(node),
            ruleId,
            title,
            description: evidence.join(" "),
            severity,
            confidence: "HIGH",
            category: "Secrets & Crypto",
            cwe,
            evidence,
            dataFlow: [],
            recommendation,
          },
          `${ruleId}:${relative}:${identity}`,
        ),
      );
    };

    const createHashAlgorithm = (node: ts.Expression): string | undefined => {
      if (!ts.isCallExpression(node) || node.arguments.length < 1)
        return undefined;
      const algorithm = node.arguments[0];
      if (!algorithm || !ts.isStringLiteralLike(algorithm)) return undefined;
      if (ts.isIdentifier(node.expression)) {
        if (!createHashImports.has(node.expression.text)) return undefined;
      } else if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        cryptoNamespaces.has(node.expression.expression.text) &&
        node.expression.name.text === "createHash"
      ) {
        // recognized namespace call
      } else return undefined;
      return algorithm.text.toLowerCase();
    };

    const visit = (node: ts.Node): void => {
      if (ts.isStringLiteralLike(node)) {
        if (databaseUrl.test(node.text))
          add(
            node,
            "REAPER-CRYPTO-001",
            "Hardcoded database credential URL",
            "HIGH",
            798,
            [
              "A database connection URL containing an embedded username/password is stored directly in source.",
              "The credential value is intentionally omitted from the finding.",
            ],
            "Move database credentials to a secret manager or server-side environment variable and rotate the exposed credential.",
            `db-url:${location(node).line}`,
          );
        if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(node.text))
          add(
            node,
            "REAPER-CRYPTO-002",
            "Private key material embedded in source",
            "CRITICAL",
            321,
            [
              "A private-key PEM marker is embedded in a source literal.",
              "Key material is intentionally omitted from the finding.",
            ],
            "Remove the private key from source history, rotate it, and load replacement key material from protected secret storage.",
            `private-key:${location(node).line}`,
          );
      }

      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "update" &&
        node.arguments[0]
      ) {
        const algorithm = createHashAlgorithm(node.expression.expression);
        const input = node.arguments[0].getText(source);
        if (
          algorithm &&
          ["md5", "sha1", "sha256", "sha512"].includes(algorithm) &&
          passwordName.test(input)
        )
          add(
            node,
            "REAPER-CRYPTO-003",
            "Fast general-purpose hash used for password-like input",
            ["md5", "sha1"].includes(algorithm) ? "HIGH" : "MEDIUM",
            916,
            [
              `Algorithm ${algorithm.toUpperCase()} is applied to password-like input.`,
              "Fast general-purpose hashes are unsuitable for password storage even when salted manually.",
            ],
            "Use a dedicated password hashing function such as Argon2id, scrypt, or bcrypt with reviewed parameters.",
            `password-hash:${algorithm}:${location(node).line}`,
          );
      }

      ts.forEachChild(node, visit);
    };
    visit(source);
  }
}
