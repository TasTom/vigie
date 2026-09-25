/**
 * Récupération d'une page distante pour l'audit SEO, bridée.
 *
 * Ce module est le seul endroit du projet qui sort sur le web à l'adresse d'un
 * visiteur. C'est donc un **proxy**, et un proxy mal écrit sert à sonder le
 * réseau depuis l'intérieur : `http://127.0.0.1:5000`, un routeur en
 * `192.168.x.x`, ou `169.254.169.254` — l'endpoint de métadonnées des
 * hébergeurs cloud, qui distribue des identifiants d'instance.
 *
 * La défense tient en un point : **l'adresse IP est contrôlée au moment de la
 * connexion**, pas avant. Vérifier un nom d'hôte par une résolution DNS séparée
 * laisse une fenêtre pendant laquelle le DNS peut répondre une adresse publique
 * au contrôle puis une adresse privée à la connexion. Ici le contrôle et la
 * connexion partagent la même résolution : Node appelle notre `lookup`, qui
 * refuse la connexion si une seule des adresses obtenues est interne.
 *
 * Conséquence pratique : `http` et `https` uniquement, et chaque saut d'une
 * redirection est revalidé — sans cela, une redirection suffirait à contourner
 * le filtre.
 *
 * Aucune dépendance : `node:http`, `node:https`, `node:dns`, `node:net` et
 * `node:zlib` suffisent. `fetch` ne permet pas d'imposer notre résolution.
 */
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const zlib = require('node:zlib');

/** Erreur porteuse d'un code, pour que le handler choisisse le statut HTTP. */
class SeoError extends Error {
  constructor(message, code, status = 400, detail = null) {
    super(message);
    this.name = 'SeoError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Identité du robot. Volontairement explicite et joignable : un site doit
 * pouvoir reconnaître qui l'appelle et s'en plaindre. Un agent qui se fait
 * passer pour Chrome est un agent qui ment.
 */
const USER_AGENT =
  'Mozilla/5.0 (compatible; AuditSEO/1.0; +https://portfolio.warult-tools.com/audit-seo)';

const DEFAULTS = {
  /** Délai par requête. Le total doit rester sous la limite d'une fonction Vercel. */
  timeoutMs: 5000,
  timeoutMsAnnexe: 2500,
  /** Octets **reçus** plafonnés : une page de 40 Mo ne doit pas être téléchargée. */
  maxBytes: 512 * 1024,
  /** Plafond après décompression, contre un « zip bomb ». */
  maxOutputBytes: 4 * 1024 * 1024,
  maxRedirects: 3,
};

/* --------------------------------------------------------------------------
   Refus des adresses internes
   -------------------------------------------------------------------------- */

/** Adresses IPv4 hors du réseau public. */
function ipv4Bloquee(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;

  const [a, b, c] = p;
  if (a === 0) return true;                       // 0.0.0.0/8 — « ce réseau »
  if (a === 10) return true;                      // privé
  if (a === 127) return true;                     // boucle locale
  if (a === 169 && b === 254) return true;        // lien local — métadonnées cloud
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;  // CGNAT
  if (a === 192 && b === 0 && c <= 2) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;  // documentation
  if (a === 203 && b === 0 && c === 113) return true;   // documentation
  if (a >= 224) return true;                      // multicast puis réservé
  return false;
}

/** Adresses IPv6 hors du réseau public, y compris les formes encapsulées. */
function ipv6Bloquee(ip) {
  // Une adresse peut porter un identifiant de zone : fe80::1%eth0.
  const v = ip.toLowerCase().split('%')[0];

  if (v === '::' || v === '::1') return true;

  // IPv4 encapsulée en décimal (::ffff:127.0.0.1) ou en hexadécimal
  // (::ffff:7f00:1). Les deux formes désignent la même adresse.
  const decimal = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (decimal) return ipv4Bloquee(decimal[1]);

  const hexadecimal = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(v);
  if (hexadecimal) {
    const haut = parseInt(hexadecimal[1], 16);
    const bas = parseInt(hexadecimal[2], 16);
    return ipv4Bloquee(`${haut >> 8}.${haut & 255}.${bas >> 8}.${bas & 255}`);
  }

  if (/^f[cd]/.test(v)) return true;        // fc00::/7 — adresses locales uniques
  if (/^fe[89ab]/.test(v)) return true;     // fe80::/10 — lien local
  if (/^ff/.test(v)) return true;           // multicast
  if (/^2001:db8/.test(v)) return true;     // documentation
  return false;
}

/** Vrai si l'adresse doit être refusée. Une famille inconnue est refusée. */
function adresseBloquee(ip) {
  if (net.isIPv4(ip)) return ipv4Bloquee(ip);
  if (net.isIPv6(ip)) return ipv6Bloquee(ip);
  return true;
}

/**
 * Résolution DNS qui refuse les adresses internes.
 *
 * Node l'appelle au moment d'ouvrir la connexion, et non à l'analyse de l'URL :
 * c'est ce qui ferme la fenêtre entre le contrôle et l'usage — vérifier un nom
 * par une résolution séparée laisserait le DNS répondre une adresse publique au
 * contrôle puis une adresse privée à la connexion. Une seule adresse interne
 * dans la réponse suffit à refuser l'hôte, même si les autres sont publiques.
 *
 * La forme de la réponse dépend de `options.all`. Node 22 active
 * `autoSelectFamily` par défaut et demande donc **toutes** les adresses
 * (`all: true`) pour tenter IPv6 puis IPv4 à la suite. Rendre une adresse
 * unique dans ce cas produit `ERR_INVALID_IP_ADDRESS`, et **chaque** site
 * public devient injoignable — le genre de panne qu'un test sur un seul
 * domaine ne montre pas. Les deux formes sont donc gérées.
 */
function resolutionBridee(hostname, options, callback) {
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err);

    const liste = Array.isArray(addresses) ? addresses : [addresses];
    if (liste.length === 0) {
      return callback(new SeoError("Nom d'hôte introuvable.", 'UNREACHABLE', 502));
    }

    const interdite = liste.find((a) => adresseBloquee(a.address));
    if (interdite) {
      return callback(new SeoError(
        "Cette adresse n'est pas accessible depuis l'extérieur.",
        'BLOCKED_ADDRESS',
        400,
      ));
    }

    // IPv4 d'abord. Beaucoup d'hébergeurs n'ont pas de connectivité IPv6
    // sortante, et une adresse IPv6 injoignable en tête ferait échouer des
    // sites parfaitement valides.
    const triees = [...liste].sort((a, b) => a.family - b.family);

    if (options && options.all) return callback(null, triees);
    return callback(null, triees[0].address, triees[0].family);
  });
}

/* --------------------------------------------------------------------------
   Analyse de l'URL demandée
   -------------------------------------------------------------------------- */

/** Vérifie le schéma et l'hôte, et renvoie un objet `URL`. */
function cibleValide(rawUrl) {
  const texte = String(rawUrl || '').trim();
  if (!texte) throw new SeoError('Indiquez une adresse à analyser.', 'INVALID_URL');

  // Une adresse tapée sans schéma (« exemple.fr ») est comprise comme du https :
  // c'est ce que le visiteur veut dire, et le refus serait incompréhensible.
  const complete = /^[a-z][a-z0-9+.-]*:/i.test(texte) ? texte : `https://${texte}`;

  let url;
  try {
    url = new URL(complete);
  } catch {
    throw new SeoError('Cette adresse est illisible.', 'INVALID_URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SeoError(
      'Seules les adresses http et https peuvent être analysées.',
      'BAD_SCHEME',
    );
  }

  // Des identifiants dans l'URL ne servent à rien ici et masquent l'hôte réel.
  if (url.username || url.password) {
    throw new SeoError('Retirez les identifiants de l\'adresse.', 'INVALID_URL');
  }

  if (!url.hostname) throw new SeoError('Cette adresse ne désigne aucun hôte.', 'INVALID_URL');

  /*
    Contrôle des littéraux d'adresse IP — **indispensable, et non redondant**.

    Node ne résout pas un nom pour une adresse IP écrite en clair : il ouvre
    directement la connexion, sans appeler le `lookup` qui porte le contrôle du
    blocage. `http://127.0.0.1/` passerait donc sans ce test, alors que
    `http://localhost/` est bien refusé — la différence entre les deux se voit
    à l'exécution, pas à la lecture.

    Un nom d'hôte reste couvert par le `lookup` : ce test-ci ne protège que les
    adresses écrites en clair. Les deux sont nécessaires.
  */
  const hote = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hote) !== 0 && adresseBloquee(hote)) {
    throw new SeoError(
      "Cette adresse n'est pas accessible depuis l'extérieur.",
      'BLOCKED_ADDRESS',
      400,
    );
  }

  return url;
}

/* --------------------------------------------------------------------------
   Requête
   -------------------------------------------------------------------------- */

/** Décompresse selon l'en-tête `content-encoding`, avec plafond de sortie. */
function decompresser(buffer, encoding) {
  const e = String(encoding || '').toLowerCase();
  const max = DEFAULTS.maxOutputBytes;
  try {
    if (e.includes('br')) return zlib.brotliDecompressSync(buffer, { maxOutputLength: max });
    if (e.includes('gzip')) return zlib.gunzipSync(buffer, { maxOutputLength: max });
    if (e.includes('deflate')) return zlib.inflateSync(buffer, { maxOutputLength: max });
  } catch {
    // Flux illisible ou plafond dépassé : on rend les octets bruts plutôt que
    // d'échouer, l'analyse signalera l'absence de HTML exploitable.
    return buffer;
  }
  return buffer;
}

function estRedirection(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/** Une requête, sans suivre les redirections. */
function requeteUne(cible, { timeoutMs, maxBytes, extraHeaders }) {
  return new Promise((resolve, reject) => {
    const lib = cible.protocol === 'https:' ? https : http;

    const req = lib.get({
      protocol: cible.protocol,
      hostname: cible.hostname,
      port: cible.port || undefined,
      path: `${cible.pathname}${cible.search}`,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
        /*
          Les en-têtes passés par l'appelant complètent l'agent, ils ne le
          remplacent pas : c'est l'audit CORS de l'outil de sécurité qui a
          besoin de poser un `Origin` synthétique, et il doit le faire sans
          pouvoir se déguiser en Chrome.
        */
        ...(extraHeaders || {}),
      },
      // Le contrôle des adresses internes a lieu ici, à l'ouverture.
      lookup: resolutionBridee,
      timeout: timeoutMs,
      headersTimeout: timeoutMs,
    }, (res) => {
      const morceaux = [];
      let recus = 0;
      let tronque = false;

      const rendre = (tronque_) => {
        const brut = Buffer.concat(morceaux);
        const html = decompresser(brut, res.headers['content-encoding']);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          html: html.toString('utf8'),
          bytesRecus: brut.length,
          bytesTexte: html.length,
          tronque: tronque_,
        });
      };

      res.on('data', (chunk) => {
        if (tronque) return;
        recus += chunk.length;
        if (recus > maxBytes) {
          // Au-delà du plafond on coupe la connexion : la page est déjà
          // inexploitable, et laisser finir le transfert coûte du temps.
          tronque = true;
          res.destroy();
          rendre(true);
          return;
        }
        morceaux.push(chunk);
      });

      res.on('end', () => { if (!tronque) rendre(false); });
      res.on('error', (err) => { if (!tronque) reject(err); });
    });

    req.on('timeout', () => {
      req.destroy(new SeoError('Le site n\'a pas répondu à temps.', 'TIMEOUT', 504));
    });

    req.on('error', (err) => reject(err));
  });
}

/**
 * Récupère une page en suivant les redirections, chacune revalidée.
 *
 * `hops` compte les redirections ; le handler s'en sert pour signaler une
 * éventuelle bascule http → https.
 */
async function recupererPage(rawUrl, options = {}) {
  const { timeoutMs, maxBytes, maxRedirects, extraHeaders } = { ...DEFAULTS, ...options };

  let cible = cibleValide(rawUrl);
  const debut = Date.now();
  const chaine = [cible.toString()];
  /*
    Détail de chaque saut, en-têtes compris.

    L'audit SEO ne se sert que de la chaîne d'URL ; l'audit de sécurité, lui,
    raisonne sur **chaque réponse** : un `Set-Cookie` posé sur une redirection,
    ou une réponse en `http` avant le `https`, n'apparaissent que là. Sans ce
    relevé, ces constats seraient invisibles — c'est tout l'intérêt de l'outil.
  */
  const sauts = [];
  let cumulRecus = 0;
  let compression = null;

  for (let saut = 0; saut <= maxRedirects; saut += 1) {
    let reponse;
    try {
      reponse = await requeteUne(cible, { timeoutMs, maxBytes, extraHeaders });
    } catch (err) {
      if (err instanceof SeoError) throw err;
      throw new SeoError(
        'Ce site est injoignable.',
        'UNREACHABLE',
        502,
        err && err.code ? err.code : null,
      );
    }

    cumulRecus += reponse.bytesRecus;
    if (reponse.headers['content-encoding']) {
      compression = String(reponse.headers['content-encoding']).split(',')[0].trim();
    }

    if (estRedirection(reponse.status)) {
      const location = reponse.headers.location;
      sauts.push({
        url: cible.toString(),
        status: reponse.status,
        location: location || null,
        headers: reponse.headers,
        setCookie: reponse.headers['set-cookie'] || [],
      });
      if (!location) {
        throw new SeoError(
          'Le site renvoie une redirection sans destination.',
          'UNREACHABLE',
          502,
        );
      }
      // `new URL(relative, base)` résout les destinations relatives.
      cible = cibleValide(new URL(location, cible).toString());
      chaine.push(cible.toString());
      continue;
    }

    sauts.push({
      url: cible.toString(),
      status: reponse.status,
      location: null,
      headers: reponse.headers,
      setCookie: reponse.headers['set-cookie'] || [],
    });

    return {
      url: chaine[0],
      urlFinale: cible.toString(),
      chaine,
      sauts,
      redirects: chaine.length - 1,
      status: reponse.status,
      headers: reponse.headers,
      html: reponse.html,
      bytesRecus: cumulRecus,
      bytesTexte: reponse.bytesTexte,
      compression,
      tronque: reponse.tronque,
      dureeMs: Date.now() - debut,
    };
  }

  throw new SeoError(
    'Le site enchaîne trop de redirections.',
    'TOO_MANY_REDIRECTS',
    502,
  );
}

/**
 * Récupère un fichier annexe (robots.txt, sitemap.xml).
 *
 * Ne lève jamais : un fichier absent est une information d'audit, pas une panne.
 * Une erreur est rendue comme telle pour que le rapport distingue « 404 » de
 * « injoignable ».
 */
async function recupererAnnexe(url, { timeoutMs = DEFAULTS.timeoutMsAnnexe } = {}) {
  try {
    const resultat = await requeteUne(cibleValide(url), {
      timeoutMs,
      maxBytes: 256 * 1024,
    });

    if (estRedirection(resultat.status)) {
      // On ne suit pas : plusieurs robots.txt redirigent vers un CMS, et suivre
      // ouvrirait autant de requêtes que le site le demande.
      return { ok: false, status: resultat.status, raison: 'redirect' };
    }

    return {
      ok: resultat.status === 200,
      status: resultat.status,
      corps: resultat.html,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      raison: err instanceof SeoError ? err.code : 'UNREACHABLE',
      bloque: err instanceof SeoError && err.code === 'BLOCKED_ADDRESS',
    };
  }
}

module.exports = {
  DEFAULTS,
  SeoError,
  USER_AGENT,
  adresseBloquee,
  cibleValide,
  /*
    Exposé pour l'audit de sécurité, qui ouvre une connexion TLS avec la même
    résolution pontée. C'est indispensable : un `tls.connect` qui résoudrait
    par lui-même contournerait le contrôle, et l'analyse du certificat
    deviendrait un second point d'entrée SSRF.
  */
  resolutionBridee,
  requeteUne,
  estRedirection,
  recupererPage,
  recupererAnnexe,
};
