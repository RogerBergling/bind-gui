/* Minimal ZIP writer/reader (store + deflate) used for multi-file import/export. */

import { fromUtf8, isSafeRelativePath, sanitizeArchivePath, utf8 } from '../utils.js';

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const EOCD_SIGNATURE = 0x06054b50;
const UTF8_FLAG = 0x0800;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (let index = 0; index < bytes.length; index += 1) {
    crc = CRC_TABLE[(crc ^ bytes[index]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(value) {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value & 0xffff, true);
  return bytes;
}

function u32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
  return bytes;
}

function dosDateTime(date = new Date()) {
  const year = Math.max(1980, date.getFullYear());
  const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  return { dosDate, dosTime };
}

async function deflateRaw(bytes) {
  if (typeof CompressionStream === 'undefined') return null;
  try {
    const stream = new CompressionStream('deflate-raw');
    const writer = stream.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const response = new Response(stream.readable);
    return new Uint8Array(await response.arrayBuffer());
  } catch {
    return null;
  }
}

async function inflateRaw(bytes, options = {}) {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot decompress deflated ZIP entries. Re-export the bundle as a stored ZIP or use a modern browser.');
  }
  const maxOutputSize = options.maxOutputSize ?? 10 * 1024 * 1024;
  const maxCompressionRatio = options.maxCompressionRatio ?? 200;
  // Allow small legitimate files to compress heavily without letting a tiny
  // payload expand into an unbounded allocation.
  const ratioLimit = Math.max(64 * 1024, bytes.length * maxCompressionRatio);
  const limit = Math.min(maxOutputSize, ratioLimit);
  const stream = new DecompressionStream('deflate-raw');
  const writer = stream.writable.getWriter();
  writer.write(bytes).catch(() => {});
  writer.close().catch(() => {});
  const reader = stream.readable.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        const error = new Error(`decompressed data exceeds the ${Math.round(limit / 1024)} KiB limit`);
        error.produced = total;
        throw error;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/**
 * Create a ZIP archive.
 * @param {Array<{path: string, content: string|Uint8Array, date?: Date}>} files
 * @param {{compress?: boolean}} options
 * @returns {Promise<Uint8Array>}
 */
export async function createZip(files, options = {}) {
  const central = [];
  const chunks = [];
  let offset = 0;
  const seen = new Set();

  const push = (bytes) => {
    chunks.push(bytes);
    offset += bytes.length;
  };

  for (const file of files || []) {
    let path = sanitizeArchivePath(file.path);
    if (!path) continue;
    if (seen.has(path)) {
      const dot = path.lastIndexOf('.');
      const stem = dot > 0 ? path.slice(0, dot) : path;
      const extension = dot > 0 ? path.slice(dot) : '';
      let counter = 2;
      while (seen.has(`${stem}-${counter}${extension}`)) counter += 1;
      path = `${stem}-${counter}${extension}`;
    }
    seen.add(path);
    const data = typeof file.content === 'string' ? utf8(file.content) : new Uint8Array(file.content || []);
    const crc = crc32(data);
    const deflated = options.compress === false ? null : await deflateRaw(data);
    const method = deflated ? 8 : 0;
    const payload = deflated || data;
    const nameBytes = utf8(path);
    const { dosDate, dosTime } = dosDateTime(file.date instanceof Date ? file.date : new Date());
    const localOffset = offset;

    push(u32(LOCAL_SIGNATURE));
    push(u16(20));
    push(u16(UTF8_FLAG));
    push(u16(method));
    push(u16(dosTime));
    push(u16(dosDate));
    push(u32(crc));
    push(u32(payload.length));
    push(u32(data.length));
    push(u16(nameBytes.length));
    push(u16(0));
    push(nameBytes);
    push(payload);

    central.push({
      path,
      nameBytes,
      method,
      dosTime,
      dosDate,
      crc,
      compressedSize: payload.length,
      uncompressedSize: data.length,
      localOffset,
    });
  }

  const centralStart = offset;
  for (const entry of central) {
    push(u32(CENTRAL_SIGNATURE));
    push(u16(20));
    push(u16(20));
    push(u16(UTF8_FLAG));
    push(u16(entry.method));
    push(u16(entry.dosTime));
    push(u16(entry.dosDate));
    push(u32(entry.crc));
    push(u32(entry.compressedSize));
    push(u32(entry.uncompressedSize));
    push(u16(entry.nameBytes.length));
    push(u16(0));
    push(u16(0));
    push(u16(0));
    push(u16(0));
    push(u32(0));
    push(u32(entry.localOffset));
    push(entry.nameBytes);
  }
  const centralSize = offset - centralStart;
  push(u32(EOCD_SIGNATURE));
  push(u16(0));
  push(u16(0));
  push(u16(central.length));
  push(u16(central.length));
  push(u32(centralSize));
  push(u32(centralStart));
  push(u16(0));

  const total = chunks.reduce((length, chunk) => length + chunk.length, 0);
  const result = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    result.set(chunk, cursor);
    cursor += chunk.length;
  }
  return result;
}

function findEndOfCentralDirectory(view) {
  const maxComment = 0xffff;
  const start = Math.max(0, view.byteLength - (22 + maxComment));
  for (let offset = view.byteLength - 22; offset >= start; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) return offset;
  }
  return -1;
}

function safeZipPath(path) {
  const normalized = String(path || '').replace(/\\/g, '/');
  if (!isSafeRelativePath(normalized)) return null;
  return sanitizeArchivePath(normalized);
}

/**
 * Read a ZIP archive. Deflate entries require DecompressionStream.
 * @param {ArrayBuffer|Uint8Array} input
 * @param {{maxEntries?: number, maxFileSize?: number, maxTotalSize?: number, maxCompressionRatio?: number}} options
 */
export async function readZip(input, options = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const maxEntries = options.maxEntries ?? 2000;
  const maxFileSize = options.maxFileSize ?? 10 * 1024 * 1024;
  const maxTotalSize = options.maxTotalSize ?? 50 * 1024 * 1024;
  const maxCompressionRatio = options.maxCompressionRatio ?? 200;
  const eocd = findEndOfCentralDirectory(view);
  if (eocd < 0) throw new Error('This file is not a readable ZIP archive.');
  const totalEntries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new Error('ZIP64 archives are not supported by this browser importer. Re-export the files as a normal ZIP.');
  }
  if (totalEntries > maxEntries) throw new Error(`The archive contains ${totalEntries} entries; the limit is ${maxEntries}.`);
  if (centralOffset + centralSize > bytes.length) throw new Error('The ZIP central directory is outside the file.');

  const files = [];
  const warnings = [];
  let cursor = centralOffset;
  let totalUncompressed = 0;
  let actualUncompressed = 0;

  for (let index = 0; index < totalEntries; index += 1) {
    if (cursor + 46 > bytes.length || view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      throw new Error('The ZIP central directory is corrupt.');
    }
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const crc = view.getUint32(cursor + 16, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const uncompressedSize = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const rawName = fromUtf8(nameBytes);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    cursor = next;
    if (rawName.endsWith('/')) continue;
    const path = safeZipPath(rawName);
    if (!path) {
      warnings.push(`Skipped unsafe archive path: ${rawName}`);
      continue;
    }
    if (flags & 0x0001) {
      warnings.push(`Skipped encrypted entry: ${rawName}`);
      continue;
    }
    if (uncompressedSize > maxFileSize) {
      warnings.push(`Skipped oversized entry: ${rawName}`);
      continue;
    }
    totalUncompressed += uncompressedSize;
    if (totalUncompressed > maxTotalSize) {
      throw new Error(`The archive expands to more than ${Math.round(maxTotalSize / 1024 / 1024)} MiB.`);
    }
    if (localOffset + 30 > bytes.length || view.getUint32(localOffset, true) !== LOCAL_SIGNATURE) {
      warnings.push(`Skipped entry with a corrupt local header: ${rawName}`);
      continue;
    }
    const localNameLength = view.getUint16(localOffset + 26, true);
    const localExtraLength = view.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    if (dataStart + compressedSize > bytes.length) {
      warnings.push(`Skipped truncated entry: ${rawName}`);
      continue;
    }
    const payload = bytes.subarray(dataStart, dataStart + compressedSize);
    let contentBytes;
    if (method === 0) {
      contentBytes = payload;
    } else if (method === 8) {
      try {
        contentBytes = await inflateRaw(payload, {
          maxOutputSize: Math.min(maxFileSize, Math.max(0, maxTotalSize - actualUncompressed)),
          maxCompressionRatio,
        });
      } catch (error) {
        actualUncompressed += Number(error.produced) || 0;
        if (actualUncompressed > maxTotalSize) {
          throw new Error(`The archive expands to more than ${Math.round(maxTotalSize / 1024 / 1024)} MiB.`);
        }
        warnings.push(`Could not decompress ${rawName}: ${error.message}`);
        continue;
      }
    } else {
      warnings.push(`Skipped ${rawName}: unsupported compression method ${method}.`);
      continue;
    }
    actualUncompressed += contentBytes.length;
    if (actualUncompressed > maxTotalSize) {
      throw new Error(`The archive expands to more than ${Math.round(maxTotalSize / 1024 / 1024)} MiB.`);
    }
    if (contentBytes.length !== uncompressedSize) {
      warnings.push(`Skipped ${rawName}: size mismatch after decompression.`);
      continue;
    }
    if (crc && crc32(contentBytes) !== crc) {
      warnings.push(`Skipped ${rawName}: CRC check failed.`);
      continue;
    }
    const binary = contentBytes.includes(0);
    if (binary) {
      warnings.push(`Skipped binary file: ${rawName}`);
      continue;
    }
    files.push({
      path,
      content: fromUtf8(contentBytes),
      size: uncompressedSize,
      crc32: crc,
    });
  }

  return { files, warnings };
}
