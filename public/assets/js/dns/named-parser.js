/* Tokenizer and structural parser for BIND named.conf files. */

import { normalizeNewlines } from '../utils.js';

function unescapeNamedString(value) {
  return String(value)
    .replace(/\\(\d{3})/g, (_, digits) => String.fromCharCode(Number(digits) % 256))
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\(.)/g, '$1');
}

export function tokenizeNamed(text, file = 'named.conf') {
  const input = normalizeNewlines(text).replace(/^\uFEFF/, '');
  const tokens = [];
  const errors = [];
  let index = 0;
  let line = 1;
  let column = 1;

  const advance = (count = 1) => {
    for (let step = 0; step < count; step += 1) {
      if (input[index] === '\n') {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
      index += 1;
    }
  };

  while (index < input.length) {
    const char = input[index];

    if (/\s/.test(char)) {
      advance();
      continue;
    }

    if (char === '#' || (char === '/' && input[index + 1] === '/')) {
      while (index < input.length && input[index] !== '\n') advance();
      continue;
    }

    if (char === '/' && input[index + 1] === '*') {
      const startLine = line;
      advance(2);
      let closed = false;
      while (index < input.length) {
        if (input[index] === '*' && input[index + 1] === '/') {
          advance(2);
          closed = true;
          break;
        }
        advance();
      }
      if (!closed) errors.push({ message: 'Unclosed block comment.', line: startLine, file });
      continue;
    }

    if (char === '{' || char === '}' || char === ';') {
      tokens.push({ type: char, value: char, line, column, file });
      advance();
      continue;
    }

    if (char === '"') {
      const startLine = line;
      const startColumn = column;
      advance();
      let raw = '';
      let closed = false;
      while (index < input.length) {
        const current = input[index];
        if (current === '\\' && index + 1 < input.length) {
          raw += current + input[index + 1];
          advance(2);
          continue;
        }
        if (current === '"') {
          advance();
          closed = true;
          break;
        }
        raw += current;
        advance();
      }
      if (!closed) errors.push({ message: 'Unclosed quoted string.', line: startLine, file });
      tokens.push({
        type: 'string',
        value: unescapeNamedString(raw),
        raw,
        quoted: true,
        line: startLine,
        column: startColumn,
        file,
      });
      continue;
    }

    const startLine = line;
    const startColumn = column;
    let value = '';
    while (index < input.length) {
      const current = input[index];
      if (/\s/.test(current) || current === '{' || current === '}' || current === ';') break;
      if (current === '#' || (current === '/' && (input[index + 1] === '/' || input[index + 1] === '*'))) break;
      if (current === '"' && value === '') break;
      value += current;
      advance();
    }
    if (value) {
      tokens.push({ type: 'word', value, raw: value, quoted: false, line: startLine, column: startColumn, file });
    } else {
      // Defensive: never loop forever on an unexpected character.
      advance();
    }
  }

  return { tokens, errors };
}

function parseStatements(tokens, file) {
  const statements = [];
  const errors = [];
  let index = 0;

  function parseBlock(stopAtBrace) {
    const result = [];
    while (index < tokens.length) {
      const token = tokens[index];
      if (token.type === ';') {
        index += 1;
        continue;
      }
      if (token.type === '}') {
        if (stopAtBrace) {
          index += 1;
          return result;
        }
        errors.push({ message: 'Unexpected closing brace.', line: token.line, file });
        index += 1;
        continue;
      }
      if (token.type === '{') {
        errors.push({ message: 'Unexpected opening brace without a statement keyword.', line: token.line, file });
        index += 1;
        const skipped = parseBlock(true);
        result.push({
          keyword: '',
          head: [],
          args: [],
          tokens: [token],
          body: skipped,
          hasBlock: true,
          line: token.line,
          endLine: skipped.at(-1)?.endLine || token.line,
          file,
        });
        continue;
      }

      const head = [];
      const startLine = token.line;
      let body = null;
      let endLine = token.line;
      let complete = false;

      while (index < tokens.length) {
        const current = tokens[index];
        if (current.type === '{') {
          index += 1;
          body = parseBlock(true);
          endLine = body.at(-1)?.endLine || current.line;
          if (tokens[index]?.type === ';') {
            endLine = tokens[index].line;
            index += 1;
          }
          complete = true;
          break;
        }
        if (current.type === ';') {
          endLine = current.line;
          index += 1;
          complete = true;
          break;
        }
        if (current.type === '}') {
          errors.push({ message: 'Statement is missing a semicolon before the closing brace.', line: current.line, file });
          endLine = current.line;
          complete = true;
          break;
        }
        head.push(current);
        endLine = current.line;
        index += 1;
      }

      if (!complete) {
        errors.push({ message: 'Statement is not terminated by a semicolon or block.', line: startLine, file });
      }
      if (head.length === 0) continue;
      const keywordToken = head[0];
      result.push({
        keyword: String(keywordToken.value).toLowerCase(),
        rawKeyword: keywordToken.value,
        head: head.slice(1),
        args: head.slice(1).map((item) => item.value),
        tokens: head,
        body: body || [],
        hasBlock: Boolean(body),
        line: startLine,
        endLine,
        file,
      });
    }
    if (stopAtBrace) {
      errors.push({ message: 'Unclosed block: reached end of file before “}”.', line: tokens.at(-1)?.line || 1, file });
    }
    return result;
  }

  const parsed = parseBlock(false);
  statements.push(...parsed);
  return { statements, errors };
}

export function parseNamed(text, options = {}) {
  const file = options.file || 'named.conf';
  const { tokens, errors: tokenErrors } = tokenizeNamed(text, file);
  const { statements, errors: parseErrors } = parseStatements(tokens, file);
  return {
    file,
    tokens,
    statements,
    errors: [...tokenErrors, ...parseErrors],
    stats: {
      statements: countStatements(statements),
      topLevel: statements.length,
      errors: tokenErrors.length + parseErrors.length,
    },
  };
}

export function countStatements(statements) {
  let count = 0;
  for (const statement of statements) {
    count += 1;
    if (statement.body?.length) count += countStatements(statement.body);
  }
  return count;
}

export function walkStatements(statements, visitor, context = []) {
  for (const statement of statements) {
    visitor(statement, context);
    if (statement.body?.length) {
      walkStatements(statement.body, visitor, [...context, statement.keyword]);
    }
  }
}

export function findStatements(statements, keyword) {
  const found = [];
  walkStatements(statements, (statement) => {
    if (statement.keyword === keyword) found.push(statement);
  });
  return found;
}

export function findTopLevel(statements, keyword) {
  return statements.filter((statement) => statement.keyword === keyword);
}

export function statementArgs(statement) {
  return (statement?.args || []).map(String);
}

export function firstArg(statement) {
  return statement?.args?.[0] ?? null;
}

export function statementLabel(statement) {
  if (!statement) return '';
  const args = statement.args || [];
  return args.length ? `${statement.keyword} ${args.map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg)).join(' ')}` : statement.keyword;
}

export function statementToText(statement, indent = '') {
  if (!statement) return '';
  const args = statement.args || [];
  const head = [statement.rawKeyword || statement.keyword, ...args.map((arg) => (/[\s;{}]/.test(arg) ? JSON.stringify(arg) : arg))].join(' ');
  if (!statement.hasBlock) return `${indent}${head};`;
  const inner = statement.body?.map((child) => statementToText(child, `${indent}  `)).join('\n') || '';
  return `${indent}${head} {\n${inner}\n${indent}};`;
}

export function flattenStatements(statements, context = [], output = []) {
  for (const statement of statements) {
    output.push({ statement, context });
    if (statement.body?.length) {
      flattenStatements(statement.body, [...context, statement.keyword], output);
    }
  }
  return output;
}
