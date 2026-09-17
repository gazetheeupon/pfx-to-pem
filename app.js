import { parsePfx, PfxError } from './pfx-parser.js';

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const passwordInput = document.getElementById('password');
const showPasswordBtn = document.getElementById('showPassword');
const convertBtn = document.getElementById('convertBtn');
const fname = document.getElementById('fname');
const status = document.getElementById('status');
const results = document.getElementById('results');

let currentFile = null;
let lastBaseName = 'certificate';

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function row(label, value) {
  if (value === null || value === undefined || value === '') return '';
  return `<tr><td>${label}</td><td>${escapeHtml(value)}</td></tr>`;
}

function updateConvertEnabled() {
  convertBtn.disabled = !currentFile;
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function render(result) {
  const c = result.certInfo;
  let html = '<h2>Certificate</h2><table>';
  html += row('Subject', c.subject);
  html += row('Issuer', c.issuer);
  html += row('Valid from', c.validFrom && c.validFrom.toUTCString ? c.validFrom.toUTCString() : c.validFrom);
  html += row('Valid to', c.validTo && c.validTo.toUTCString ? c.validTo.toUTCString() : c.validTo);
  html += row('Serial number', c.serialNumber);
  html += row('SHA-256 fingerprint', c.fingerprintSha256);
  html += row('Self-signed', c.isSelfSigned ? 'Yes' : 'No');
  html += '</table>';

  if (result.chainInfo && result.chainInfo.length) {
    html += '<h2>Additional chain certificates</h2><table>';
    result.chainInfo.forEach((ci, i) => {
      html += row(`#${i + 1} subject`, ci.subject);
    });
    html += '</table>';
  }

  html += '<div class="downloads">';
  html += '<button class="exp" id="dlCert">Download certificate.pem</button>';
  if (result.hasKey) html += '<button class="exp" id="dlKey">Download private-key.pem</button>';
  if (result.chainPem) html += '<button class="exp" id="dlChain">Download ca-chain.pem</button>';
  html += '<button class="exp" id="dlAll">Download all-in-one .pem</button>';
  html += '</div>';
  html += '<p class="note">Nothing here was uploaded &mdash; the file above was read and converted entirely in this browser tab.</p>';

  results.innerHTML = html;

  document.getElementById('dlCert').addEventListener('click', () => download(`${lastBaseName}-cert.pem`, result.certPem, 'application/x-pem-file'));
  if (result.hasKey) {
    document.getElementById('dlKey').addEventListener('click', () => download(`${lastBaseName}-key.pem`, result.keyPem, 'application/x-pem-file'));
  }
  if (result.chainPem) {
    document.getElementById('dlChain').addEventListener('click', () => download(`${lastBaseName}-chain.pem`, result.chainPem, 'application/x-pem-file'));
  }
  document.getElementById('dlAll').addEventListener('click', () => {
    const all = [result.certPem, result.keyPem, result.chainPem].filter(Boolean).join('\n');
    download(`${lastBaseName}-bundle.pem`, all, 'application/x-pem-file');
  });
}

function handleFile(file) {
  if (!file) return;
  currentFile = file;
  lastBaseName = file.name.replace(/\.[^.]+$/, '') || 'certificate';
  fname.textContent = file.name;
  updateConvertEnabled();
  status.textContent = '';
  results.innerHTML = '';
}

async function doConvert() {
  if (!currentFile) return;
  status.textContent = 'Reading and decrypting...';
  results.innerHTML = '';
  try {
    const buf = await currentFile.arrayBuffer();
    const result = parsePfx(buf, passwordInput.value);
    render(result);
    status.textContent = 'Done.';
  } catch (err) {
    if (err instanceof PfxError) {
      status.textContent = 'Error: ' + err.message;
    } else {
      status.textContent = 'Unexpected error: ' + err.message;
      console.error(err);
    }
  }
}

showPasswordBtn.addEventListener('click', () => {
  passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
  showPasswordBtn.textContent = passwordInput.type === 'password' ? 'Show' : 'Hide';
});

convertBtn.addEventListener('click', doConvert);
passwordInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doConvert(); });

dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));
['dragenter', 'dragover'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); })
);
['dragleave', 'drop'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); })
);
dropzone.addEventListener('drop', (e) => handleFile(e.dataTransfer.files[0]));
