/*! Eretek Online Araçlar #20 — DKIM Selector Sorgulayıcı */
ERT.def('20', {
	run: function (v, c) {
		var D = ERT.dns, d = D.normName(v.domain), s = String(v.sel || '').trim().toLowerCase();
		if (!d) { throw c.fe('domain', 'badDomain'); }
		if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(s)) { throw c.fe('sel', 'badSel'); }
		var name = s + '._domainkey.' + d;
		return D.txt(name).then(function (r) {
			var msgs = [], kv = [[c.t('qname'), name]];
			if (r.chain.length) { kv.push([c.t('cname'), r.chain.join(' → ')]); }
			if (r.status !== 'ok') { msgs.push([r.status === 'nodata' || r.status === 'nxdomain' ? 'warn' : 'err', c.t('st_' + r.status)]); return { big: c.t('none'), kv: kv, msgs: msgs, v: { status: r.status } }; }
			var rec = r.texts.join(''), tags = {};
			if (r.texts.length > 1) { msgs.push(['warn', c.t('multi', { n: r.texts.length })]); rec = r.texts[0]; }
			rec.split(';').forEach(function (p) { var k = p.indexOf('='); if (k > 0) { tags[p.slice(0, k).trim().toLowerCase()] = p.slice(k + 1).replace(/\s+/g, ''); } });
			var vv = { status: 'ok', k: tags.k || 'rsa', revoked: false, bits: null };
			if (tags.v && tags.v !== 'DKIM1') { msgs.push(['err', c.t('badV')]); }
			kv.push(['v', tags.v || '–'], ['k', tags.k || 'rsa (' + c.t('def') + ')'], ['h', tags.h || c.t('anyH')], ['t', tags.t || '–'], ['s', tags.s || '*']);
			if (!('p' in tags)) { msgs.push(['err', c.t('noP')]); }
			else if (tags.p === '') { vv.revoked = true; msgs.push(['warn', c.t('revoked')]); }
			else {
				var bits = null;
				try {
					var raw = atob(tags.p), b = []; for (var i = 0; i < raw.length; i++) { b.push(raw.charCodeAt(i)); }
					if ((tags.k || 'rsa') === 'rsa') { bits = ERT.asn1 ? ERT.asn1.rsaBits(b) : null; } else if (tags.k === 'ed25519') { bits = b.length === 32 ? 256 : null; }
					kv.push([c.t('keyLen'), bits ? bits + ' bit' : c.t('unknown')]);
					if (bits && (tags.k || 'rsa') === 'rsa' && bits < 1024) { msgs.push(['err', c.t('weak', { b: bits })]); }
					else if (bits && (tags.k || 'rsa') === 'rsa' && bits < 2048) { msgs.push(['warn', c.t('short', { b: bits })]); }
				} catch (e) { msgs.push(['err', c.t('badB64')]); }
				vv.bits = bits;
			}
			if (/y/.test(tags.t || '')) { msgs.push(['info', c.t('testing')]); }
			msgs.push(['info', c.t('noVerify')]);
			return { big: vv.revoked ? c.t('revokedB') : c.t('found', { s: s }), kv: kv, msgs: msgs, pre: { h: 'TXT', text: rec }, x: { copy: rec }, v: vv };
		});
	}
});
