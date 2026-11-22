/*! Eretek — DER/ASN.1, PEM, X.509 sertifika ve PKCS#10 CSR okuyucu. Ağ isteği yapmaz; güven zinciri doğrulaması yapmaz. */
(function (root) {
	'use strict';
	var ERT = root.ERT = root.ERT || {};
	var OID = {
		'2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
		'1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448', '1.2.840.10040.4.1': 'DSA',
		'1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption', '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS', '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
		'1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
		'1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
		'2.5.29.17': 'subjectAltName', '2.5.29.19': 'basicConstraints', '2.5.29.15': 'keyUsage', '2.5.29.37': 'extKeyUsage', '1.2.840.113549.1.9.14': 'extensionRequest',
		'1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth', '1.3.6.1.5.5.7.3.3': 'codeSigning', '1.3.6.1.5.5.7.3.4': 'emailProtection'
	};
	function AsnErr(m) { this.message = m; }
	function read(b, pos) {
		if (pos + 2 > b.length) { throw new AsnErr('eof'); }
		var tag = b[pos], p = pos + 1, len = b[p++];
		if (len & 0x80) { var n = len & 0x7f; if (n < 1 || n > 4) { throw new AsnErr('len'); } len = 0; for (var i = 0; i < n; i++) { len = len * 256 + b[p++]; } }
		if (p + len > b.length) { throw new AsnErr('eof'); }
		var node = { tag: tag, cls: tag >> 6, cons: !!(tag & 0x20), num: tag & 0x1f, start: pos, hs: p, end: p + len, len: len, kids: null };
		if (node.cons) { node.kids = []; var q = p; while (q < node.end) { var k = read(b, q); node.kids.push(k); q = k.end; } }
		return node;
	}
	function oid(b, n) {
		var v = b.slice(n.hs, n.end), out = [Math.floor(v[0] / 40), v[0] % 40], x = 0;
		for (var i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(x); x = 0; } }
		return out.join('.');
	}
	function str(b, n) {
		var v = b.slice(n.hs, n.end);
		if (n.tag === 0x1e) { var s = ''; for (var i = 0; i + 1 < v.length; i += 2) { s += String.fromCharCode(v[i] << 8 | v[i + 1]); } return s; }
		try { return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(v)); } catch (e) { return String.fromCharCode.apply(null, v); }
	}
	function hex(a, sep) { return Array.prototype.map.call(a, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(sep === undefined ? '' : sep); }
	function time(b, n) {
		var s = str(b, n), m;
		if (n.tag === 0x17) { m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s); if (!m) { return null; } var y = +m[1]; y += y < 50 ? 2000 : 1900; return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))); }
		m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s); if (!m) { return null; }
		return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
	}
	function name(b, n) {
		var parts = [];
		(n.kids || []).forEach(function (set) { (set.kids || []).forEach(function (atv) { var k = OID[oid(b, atv.kids[0])] || oid(b, atv.kids[0]); parts.push([k, str(b, atv.kids[1])]); }); });
		return parts;
	}
	function nameStr(p) { return p.map(function (x) { return x[0] + '=' + x[1]; }).join(', '); }
	function intBits(b, n) { var i = n.hs; while (i < n.end && b[i] === 0) { i++; } if (i >= n.end) { return 0; } var bits = (n.end - i - 1) * 8, top = b[i]; while (top) { bits++; top >>= 1; } return bits; }
	function spki(b, n) {
		var algo = OID[oid(b, n.kids[0].kids[0])] || oid(b, n.kids[0].kids[0]), bits = null, curve = null;
		var bs = n.kids[1], key = b.slice(bs.hs + 1, bs.end);
		if (algo === 'RSA') { var r = read(key, 0); bits = intBits(key, r.kids[0]); }
		else if (algo === 'EC') { var prm = n.kids[0].kids[1]; curve = prm && prm.tag === 6 ? (OID[oid(b, prm)] || oid(b, prm)) : null; bits = { 'P-256': 256, 'P-384': 384, 'P-521': 521 }[curve] || null; }
		else if (algo === 'Ed25519') { bits = 256; }
		return { algo: algo, bits: bits, curve: curve };
	}
	function exts(b, list) {
		var out = { san: [], ku: null, eku: [], ca: null };
		(list || []).forEach(function (e) {
			var id = OID[oid(b, e.kids[0])] || oid(b, e.kids[0]), os = e.kids[e.kids.length - 1], inner;
			try { inner = read(b.slice(os.hs, os.end), 0); } catch (x) { return; }
			var ib = b.slice(os.hs, os.end);
			if (id === 'subjectAltName') {
				inner.kids.forEach(function (g) {
					if (g.num === 2) { out.san.push('DNS:' + str(ib, g)); }
					else if (g.num === 7) { var v = ib.slice(g.hs, g.end); out.san.push('IP:' + (v.length === 4 ? v.join('.') : hex(v).match(/.{4}/g).join(':'))); }
					else if (g.num === 1) { out.san.push('email:' + str(ib, g)); }
					else if (g.num === 6) { out.san.push('URI:' + str(ib, g)); }
				});
			} else if (id === 'extKeyUsage') { inner.kids.forEach(function (k) { out.eku.push(OID[oid(ib, k)] || oid(ib, k)); }); }
			else if (id === 'basicConstraints') { out.ca = !!(inner.kids && inner.kids[0] && inner.kids[0].tag === 1 && ib[inner.kids[0].hs]); }
		});
		return out;
	}
	/** PEM metninden bloklar: [{label, der:Array}] */
	function pem(text) {
		var re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g, m, out = [];
		while ((m = re.exec(String(text || '')))) {
			var b64 = m[2].replace(/^[A-Za-z-]+:.*$/gm, '').replace(/[^A-Za-z0-9+/=]/g, ''), raw;
			try { raw = atob(b64); } catch (e) { throw new AsnErr('b64'); }
			var a = new Array(raw.length); for (var i = 0; i < raw.length; i++) { a[i] = raw.charCodeAt(i); }
			out.push({ label: m[1], der: a });
		}
		return out;
	}
	function cert(der) {
		var b = der, top = read(b, 0), tbs = top.kids[0], k = tbs.kids, i = 0, ver = 1;
		if (k[0].cls === 2 && k[0].num === 0) { ver = b[k[0].kids[0].hs] + 1; i = 1; }
		var serial = hex(b.slice(k[i].hs, k[i].end), ':'), sig = OID[oid(b, k[i + 1].kids[0])] || oid(b, k[i + 1].kids[0]);
		var issuer = name(b, k[i + 2]), validity = k[i + 3], subject = name(b, k[i + 4]), pk = spki(b, k[i + 5]);
		var ext = null; for (var j = i + 6; j < k.length; j++) { if (k[j].cls === 2 && k[j].num === 3) { ext = k[j].kids[0].kids; } }
		var e = exts(b, ext);
		return { version: ver, serial: serial, sigAlg: sig, issuer: issuer, subject: subject, notBefore: time(b, validity.kids[0]), notAfter: time(b, validity.kids[1]), key: pk, san: e.san, eku: e.eku, ca: e.ca, der: der };
	}
	function csr(der) {
		var b = der, top = read(b, 0), cri = top.kids[0], k = cri.kids;
		var subject = name(b, k[1]), pk = spki(b, k[2]), san = [], eku = [];
		if (k[3] && k[3].cls === 2) {
			(k[3].kids || []).forEach(function (attr) {
				if ((OID[oid(b, attr.kids[0])] || '') === 'extensionRequest') { var e = exts(b, attr.kids[1].kids[0].kids); san = e.san; eku = e.eku; }
			});
		}
		return { subject: subject, key: pk, san: san, eku: eku, sigAlg: OID[oid(b, top.kids[1].kids[0])] || oid(b, top.kids[1].kids[0]) };
	}
	/** SPKI (DKIM p=) içindeki RSA modül bit uzunluğu */
	function rsaBits(bytes) { try { var n = read(bytes, 0); return spki(bytes, n).bits; } catch (e) { return null; } }
	/** RFC 6125 tarzı ad eşleşmesi: joker yalnız en soldaki tam etiket */
	function matchHost(host, sans, cn) {
		host = String(host || '').toLowerCase().replace(/\.$/, '');
		var names = sans.filter(function (s) { return s.indexOf('DNS:') === 0; }).map(function (s) { return s.slice(4).toLowerCase(); });
		var ips = sans.filter(function (s) { return s.indexOf('IP:') === 0; }).map(function (s) { return s.slice(3); });
		if (!names.length && !ips.length && cn) { names = [cn.toLowerCase()]; }
		if (ips.indexOf(host) !== -1) { return true; }
		return names.some(function (n) {
			if (n === host) { return true; }
			if (n.indexOf('*.') === 0) { var rest = n.slice(1); return host.slice(-rest.length) === rest && host.slice(0, -rest.length).indexOf('.') === -1 && host.length > rest.length; }
			return false;
		});
	}
	function digest(alg, bytes) { return root.crypto.subtle.digest(alg, new Uint8Array(bytes)).then(function (h) { return hex(new Uint8Array(h), ':').toUpperCase(); }); }
	ERT.asn1 = { read: read, oid: oid, pem: pem, cert: cert, csr: csr, rsaBits: rsaBits, matchHost: matchHost, nameStr: nameStr, hex: hex, digest: digest, OID: OID, AsnErr: AsnErr };
}(typeof window !== 'undefined' ? window : globalThis));
