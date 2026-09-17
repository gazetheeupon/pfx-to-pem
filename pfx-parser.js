// Parses a password-protected PKCS#12 (.pfx / .p12) file entirely in the
// browser tab using node-forge (self-hosted, no CDN, no network calls of any
// kind) and splits it into PEM-encoded certificate, private key, and CA
// chain. The password and private key material never leave this function.
//
// forge (global, loaded via <script src="forge.min.js">) is required to be
// present on window before this module is used.

export class PfxError extends Error {}

function localKeyIdToString(attrs) {
  if (!attrs || !attrs.localKeyId || !attrs.localKeyId[0]) return null;
  // forge stores this as a binary-string-like value; use it directly as a map key.
  return attrs.localKeyId[0];
}

export function parsePfx(arrayBuffer, password) {
  const forge = window.forge;
  if (!forge) throw new PfxError('Crypto library failed to load.');

  const bytes = new Uint8Array(arrayBuffer);
  let binaryStr = '';
  for (let i = 0; i < bytes.length; i++) binaryStr += String.fromCharCode(bytes[i]);

  let p12Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(binaryStr);
  } catch (err) {
    throw new PfxError('This does not look like a valid PKCS#12 (.pfx/.p12) file: ' + err.message);
  }

  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  } catch (err) {
    if (/mac could not be verified/i.test(err.message)) {
      throw new PfxError('Incorrect password (the integrity check on the file failed).');
    }
    throw new PfxError('Could not decrypt this file: ' + err.message);
  }

  const certBagsMap = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certBags = certBagsMap[forge.pki.oids.certBag] || [];

  let keyBags = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]) || [];
  if (keyBags.length === 0) {
    keyBags = (p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]) || [];
  }

  if (certBags.length === 0) {
    throw new PfxError('No certificates found inside this file.');
  }

  const keyBag = keyBags[0] || null;
  const keyLocalId = keyBag ? localKeyIdToString(keyBag.attributes) : null;

  let leafBag = null;
  const otherCerts = [];
  for (const bag of certBags) {
    const id = localKeyIdToString(bag.attributes);
    if (leafBag === null && keyLocalId !== null && id === keyLocalId) {
      leafBag = bag;
    } else {
      otherCerts.push(bag);
    }
  }
  // Fallback: if nothing matched by localKeyId (some tools omit it entirely,
  // or there's exactly one cert), treat the first cert as the leaf.
  if (!leafBag) {
    leafBag = certBags[0];
    otherCerts.length = 0;
    for (let i = 1; i < certBags.length; i++) otherCerts.push(certBags[i]);
  }

  const leafCert = leafBag.cert;
  const certPem = forge.pki.certificateToPem(leafCert);
  const chainPem = otherCerts.map((b) => forge.pki.certificateToPem(b.cert)).join('\n');
  const keyPem = keyBag ? forge.pki.privateKeyToPem(keyBag.key) : null;

  function fieldOrNull(attrObj, name) {
    try {
      const f = attrObj.getField(name);
      return f ? f.value : null;
    } catch {
      return null;
    }
  }

  function describeCert(cert) {
    const subjectParts = cert.subject.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(', ');
    const issuerParts = cert.issuer.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(', ');
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha256.create();
    md.update(der);
    const fingerprint = md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();
    return {
      subject: subjectParts,
      issuer: issuerParts,
      commonName: fieldOrNull(cert.subject, 'CN'),
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
      serialNumber: cert.serialNumber,
      fingerprintSha256: fingerprint,
      isSelfSigned: subjectParts === issuerParts,
    };
  }

  return {
    certPem,
    keyPem,
    chainPem: chainPem || null,
    certInfo: describeCert(leafCert),
    chainInfo: otherCerts.map((b) => describeCert(b.cert)),
    hasKey: !!keyPem,
  };
}
