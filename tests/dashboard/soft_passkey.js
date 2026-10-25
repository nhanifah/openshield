// Software passkey for testing the dashboard's passkey flows without a
// real authenticator. Paste into the browser console (or inject with a
// browser automation tool) on the dashboard page: it replaces
// navigator.credentials.create/get with an ES256 (P-256) authenticator held
// in memory, which sends exactly what Touch ID or a security key would.
// For testing only; never load it into a real operator's browser.
(() => {
  const enc = new TextEncoder();
  const keys = (window.__softPasskeys = window.__softPasskeys || []);
  const cat = (...a) => {
    const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
    let i = 0;
    for (const x of a) { o.set(x, i); i += x.length; }
    return o;
  };
  const head = (m, n) => new Uint8Array(n < 24 ? [(m << 5) | n] : n < 256 ? [(m << 5) | 24, n] : [(m << 5) | 25, n >> 8, n & 255]);
  const cbor = (v) => {
    if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
    if (v instanceof Uint8Array) return cat(head(2, v.length), v);
    if (typeof v === 'string') { const b = enc.encode(v); return cat(head(3, b.length), b); }
    if (v instanceof Map) { const p = [head(5, v.size)]; for (const [k, x] of v) p.push(cbor(k), cbor(x)); return cat(...p); }
    throw new Error('cbor: unsupported value');
  };
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const u8 = (b) => (b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
  const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  // WebCrypto returns r||s; WebAuthn ES256 signatures are ASN.1 DER.
  const der = (raw) => {
    const int = (b) => {
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      b = b.slice(i);
      if (b[0] & 0x80) b = cat(new Uint8Array([0]), b);
      return cat(new Uint8Array([2, b.length]), b);
    };
    const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
    return cat(new Uint8Array([0x30, r.length + s.length]), r, s);
  };
  const clientData = (type, challenge) =>
    enc.encode(JSON.stringify({ type, challenge: b64u(u8(challenge)), origin: location.origin, crossOrigin: false }));
  const flags = { up: 0x01, uv: 0x04, at: 0x40 };

  navigator.credentials.create = async ({ publicKey: o }) => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const id = crypto.getRandomValues(new Uint8Array(16));
    const rpId = (o.rp && o.rp.id) || location.hostname;
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33)]]));
    const ad = cat(await sha(enc.encode(rpId)), new Uint8Array([flags.up | flags.uv | flags.at, 0, 0, 0, 0]),
      new Uint8Array(16), new Uint8Array([0, id.length]), id, cose);
    keys.push({ id, key: kp.privateKey, rpId });
    const att = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', ad]]));
    return { id: b64u(id), rawId: id.buffer, type: 'public-key',
      response: { clientDataJSON: clientData('webauthn.create', o.challenge).buffer, attestationObject: att.buffer, getTransports: () => ['internal'] } };
  };

  navigator.credentials.get = async ({ publicKey: o }) => {
    const k = keys.filter((x) => x.rpId === (o.rpId || location.hostname)).pop();
    if (!k) { const e = new Error('No passkey for this site.'); e.name = 'NotAllowedError'; throw e; }
    const cd = clientData('webauthn.get', o.challenge);
    const ad = cat(await sha(enc.encode(k.rpId)), new Uint8Array([flags.up | flags.uv, 0, 0, 0, 0]));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.key, cat(ad, await sha(cd))));
    return { id: b64u(k.id), rawId: k.id.buffer, type: 'public-key',
      response: { clientDataJSON: cd.buffer, authenticatorData: ad.buffer, signature: der(sig).buffer, userHandle: null } };
  };
  return 'software passkey installed (' + keys.length + ' keys)';
})();
