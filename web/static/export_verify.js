/* SHA-256 verification of the original file bytes; no network requests. */
(function (root) {
  "use strict";

  function parseChecksum(text, filename) {
    if (typeof text !== "string" || text.length > 4096) {
      throw new Error("Invalid checksum file.");
    }
    text = text.replace(/^\uFEFF/, "").replace(/\r?\n$/, "");
    const match = /^([a-fA-F0-9]{64})  ([^\r\n]+)$/.exec(text);
    if (!match || /[\\/:\x00-\x1f\x7f]/.test(match[2]) || match[2] !== match[2].trim() ||
        match[2] === "." || match[2] === ".." || match[2] !== filename) {
      throw new Error("Invalid checksum or filename. Select the original CSV and its matching checksum.");
    }
    return match[1].toLowerCase();
  }

  async function verifyFiles(csvFile, checksumFile, cryptoProvider) {
    if (!csvFile || !checksumFile) {
      throw new Error("Choose both the CSV and checksum files.");
    }
    if (checksumFile.size > 4096) {
      throw new Error("The checksum file is too large.");
    }
    const provider = cryptoProvider || root.crypto;
    if (!provider || !provider.subtle) {
      throw new Error("SHA-256 needs localhost or HTTPS. Open NotesApp at http://localhost:8080, or use verify_export.py.");
    }
    const expected = parseChecksum(await checksumFile.text(), csvFile.name);
    const bytes = await csvFile.arrayBuffer();
    const digest = await provider.subtle.digest("SHA-256", bytes);
    const actual = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    return { matches: actual === expected, actual: actual, expected: expected };
  }

  const api = { parseChecksum: parseChecksum, verifyFiles: verifyFiles };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.ExportIntegrity = api;
  if (!root.document) return;
  const form = root.document.getElementById("verify-export-form");
  if (!form) return;
  const csv = root.document.getElementById("csv-file");
  const checksum = root.document.getElementById("checksum-file");
  const result = root.document.getElementById("verify-result");
  const details = root.document.getElementById("verify-details");
  const button = root.document.getElementById("verify-button");

  function clearResult() {
    result.textContent = "";
    result.style.color = "";
    details.hidden = true;
    details.textContent = "";
  }
  csv.addEventListener("change", clearResult);
  checksum.addEventListener("change", clearResult);
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    clearResult();
    result.textContent = "Checking...";
    button.disabled = csv.disabled = checksum.disabled = true;
    try {
      const checked = await verifyFiles(csv.files[0], checksum.files[0]);
      result.textContent = checked.matches
        ? "PASS - file matches its SHA-256 checksum."
        : "FAIL - file does not match its SHA-256 checksum.";
      result.style.color = checked.matches ? "#2d7d46" : "#b4461f";
      details.textContent = "Expected: " + checked.expected + "\nActual:   " + checked.actual;
      details.hidden = false;
    } catch (error) {
      result.textContent = error.message;
      result.style.color = "#b4461f";
    } finally {
      button.disabled = csv.disabled = checksum.disabled = false;
    }
  });
})(typeof globalThis !== "undefined" ? globalThis : this);
