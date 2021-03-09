        function b64ToUint6(nChr) {
          return nChr > 64 && nChr < 91 ?
            nChr - 65
            : nChr > 96 && nChr < 123 ?
              nChr - 71
              : nChr > 47 && nChr < 58 ?
                nChr + 4
                : nChr === 43 ?
                  62
                  : nChr === 47 ?
                    63
                    :
                    0;
        }

        export function base64DecToArr(sBase64, nBlockSize) {
          var sB64Enc = sBase64.replace(/[^A-Za-z0-9+/]/g, "");
          var nInLen = sB64Enc.length;
          var nOutLen = nBlockSize ? Math.ceil((nInLen * 3 + 1 >>> 2) / nBlockSize) * nBlockSize : nInLen * 3 + 1 >>> 2;
          var aBytes = new Uint8Array(nOutLen);

          for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
            nMod4 = nInIdx & 3;
            nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
            if (nMod4 === 3 || nInLen - nInIdx === 1) {
              for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++ , nOutIdx++) {
                aBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
              }
              nUint24 = 0;
            }
          }

          return aBytes;
        }

        /* Base64 string to array encoding */

        function uint6ToB64(nUint6) {
          return nUint6 < 26 ?
            nUint6 + 65
            : nUint6 < 52 ?
              nUint6 + 71
              : nUint6 < 62 ?
                nUint6 - 4
                : nUint6 === 62 ?
                  43
                  : nUint6 === 63 ?
                    47
                    :
                    65;

        }

export function base64EncArr(aBytes) {

    var eqLen = (3 - (aBytes.length % 3)) % 3, sB64Enc = "";

    for (var nMod3, nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
        nMod3 = nIdx % 3;
        /* Uncomment the following line in order to split the output in lines 76-character long: */
        /*
        if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
        */
        nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
        if (nMod3 === 2 || aBytes.length - nIdx === 1) {
            sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63), uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
            nUint24 = 0;
        }
    }

    return eqLen === 0 ?
        sB64Enc
        :
        sB64Enc.substring(0, sB64Enc.length - eqLen) + (eqLen === 1 ? "=" : "==");

}

export function importAsPrivateKey(jwk) {
    return window.crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

export function importAsPublicKey(jwk) {
    const pk = {...jwk};
    delete pk.d;
    delete pk.key_ops;

    return window.crypto.subtle.importKey('jwk', pk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}

export function hexEncArr(buffer) {
    let s = '';
    const h = '0123456789ABCDEF';
    new Uint8Array(buffer).forEach(v => s += h[v >> 4] + h[v & 15]);
    return s;
}

export async function getResearcherPrivateKey() {
    // this should be replaced by a proper key store
    let privateKey = localStorage.getItem('researcherPrivateKey');
    if (privateKey === null) {
        const keypair = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
        const key = await window.crypto.subtle.exportKey('jwk', keypair.privateKey);
        privateKey = JSON.stringify(key);
        localStorage.setItem('researcherPrivateKey', privateKey);
    }
    return window.crypto.subtle.importKey('jwk', JSON.parse(privateKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

export async function getResearcherPublicKey() {
    getResearcherPrivateKey();
    // this should be replaced by a proper key store
    let privateKey = localStorage.getItem('researcherPrivateKey');
    let publicKey = await importAsPublicKey(JSON.parse(privateKey));
    const key = await window.crypto.subtle.exportKey('raw', publicKey);
    return base64EncArr(new Uint8Array(key));
}

export function signatureToASN1(signature) {
    signature = new Uint8Array(signature);

    let r = new Uint8Array(33);
    r.set(signature.slice(0, 32), 1);

    let s = new Uint8Array(33);
    s.set(signature.slice(32, 64), 1);

	while (r[0] === 0 && r[1] < 128) {
		r = r.slice(1);
	}

	while (s[0] === 0 && s[1] < 128) {
		s = s.slice(1);
	}

	const asn1 = new Uint8Array(6 + r.length + s.length);
	asn1[0] = 0x30;
	asn1[1] = asn1.length - 2;
	asn1[2] = 0x02;
	asn1[3] = r.length;
    asn1.set(r, 4);
	asn1[4 + r.length] = 0x02;
	asn1[5 + r.length] = s.length;
    asn1.set(s, 6 + r.length);

    return base64EncArr(asn1);
}

export default {
    importAsPrivateKey,
    importAsPublicKey,
    base64DecToArr,
    base64EncArr,
    hexEncArr,
    getResearcherPrivateKey,
    getResearcherPublicKey,
    signatureToASN1
};
