/**
 * Analyse TLS d'un hôte : version négociée, chiffrement, certificat, chaîne.
 *
 * ## Pourquoi un module à part
 *
 * `fetch-page.js` parle HTTP. Le protocole de négociation et le certificat
 * se lisent sur la connexion, pas sur la réponse : les ouvrir demande un
 * `tls.connect` distinct, et c'est ce que fait ce module.
 *
 * ## Le point de sécurité
 *
 * Ce `tls.connect` **réutilise la résolution pontée** de `fetch-page.js` au
 * lieu de résoudre par lui-même. Sans cela, l'audit de certificat serait un
 * second point d'entrée SSRF indépendant du premier : un nom d'hôte pourrait
 * être refusé par le proxy HTTP et accepté par la sonde TLS, ou l'inverse.
 * Une seule défense, appliquée deux fois.
 *
 * ## `rejectUnauthorized: false`
 *
 * Volontaire, et c'est le cœur de l'outil : un certificat **expiré**, mal
 * émis ou inadapté à l'hôte est précisément ce qu'on cherche à détecter. Avec
 * la vérification activée, la connexion serait levée à la handshake et le
 * constat — le plus important de tous — deviendrait impossible à formuler. La
 * vérification est refaite ici, à la main, sur le certificat obtenu.
 */
const tls = require('node:tls');
const crypto = require('node:crypto');

const { resolutionBridee, SeoError } = require('./fetch-page');

/** Délai d'ouverture. Au-delà, le site est compté comme sans TLS exploitable. */
const TIMEOUT_MS = 6000;

/**
 * Extensions de nom d'un certificat, rendues lisibles.
 *
 * `subjectAltName` arrive en texte OpenSSL : `DNS:exemple.fr, DNS:www.exemple.fr`.
 * Une entrée `IP Address:` désigne une adresse, pas un nom : la distinguer
 * compte, car un certificat valide sur une IP ne valide pas un nom d'hôte.
 */
function lireAltNames(subjectAltName) {
  if (!subjectAltName) return { dns: [], ip: [] };

  const dns = [];
  const ip = [];

  for (const partie of String(subjectAltName).split(',')) {
    const brut = partie.trim();
    const dnsMatch = /^DNS:(.+)$/i.exec(brut);
    const ipMatch = /^IP Address:(.+)$/i.exec(brut);
    if (dnsMatch) dns.push(dnsMatch[1].trim().toLowerCase());
    else if (ipMatch) ip.push(ipMatch[1].trim());
  }

  return { dns, ip };
}

/** Un nom d'hôte « nu » : ni point, ni deux-points — donc pas une IP. */
function estNomHote(hostname) {
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && !hostname.includes(':');
}

/**
 * Résout un hôte en un objet de fait, sans jamais lever.
 *
 * Le refus d'adresse interne est **conservé** : si le proxy le refuse, la sonde
 * doit le dire, pas contourner. `bloque` distingue « on n'a pas regardé » de
 * « on a regardé et il n'y a pas de TLS ».
 */
function analyserTls(hostname, port = 443, { timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    let socket;
    try {
      socket = tls.connect({
        host: hostname,
        port,
        servername: estNomHote(hostname) ? hostname : undefined,
        // Voir l'en-tête du module : la vérification est refaite ici.
        rejectUnauthorized: false,
        // Le serveur choisit toujours la version la plus haute qu'il propose ;
        // un plancher bas ne l'oblige pas à descendre.
        minVersion: 'TLSv1',
        lookup: resolutionBridee,
        timeout: timeoutMs,
      });
    } catch (err) {
      resolve({ ok: false, erreur: err && err.code ? err.code : 'TLS_ERROR' });
      return;
    }

    let repondu = false;
    const terminer = (resultat) => {
      if (repondu) return;
      repondu = true;
      // `destroy` plutôt que `end` : on a lu le certificat, on n'a rien à
      // dire de plus, et une socket laissée ouverte tiendrait la fonction
      // serverless en vie jusqu'à son expiration.
      if (socket) socket.destroy();
      resolve(resultat);
    };

    socket.on('error', (err) => {
      if (err instanceof SeoError) {
        terminer({ ok: false, bloque: true, erreur: err.code });
        return;
      }
      terminer({ ok: false, erreur: err && err.code ? err.code : 'TLS_ERROR' });
    });

    socket.on('timeout', () => terminer({ ok: false, erreur: 'ETIMEDOUT' }));

    socket.on('secureConnect', () => {
      try {
        const protocole = socket.getProtocol();

        /*
          `socket.getCipher()` et non `socket.getSession().getCipher()`.

          Le second est déprécié depuis Node 17 et renvoie `undefined` sur les
          versions récentes — le constat aurait affiché « pas de chiffrement »
          sur une connexion parfaitement chiffrée, ce qui est le pire genre de
          défaut pour un outil de sécurité : il signale une absence qui n'existe
          pas, et l'utilisateur ne distingue plus les vrais constats.
        */
        const chiffrement = typeof socket.getCipher === 'function' ? socket.getCipher() : null;

        const brut = socket.getPeerCertificate(true);
        const erreurs = socket.authorizationError;

        // Chaîne : le premier certificat est celui du serveur, les suivants
        // sont les intermédiaires. Un serveur qui n'en expose aucun est
        // mucosal cas normal quand la racine est déjà dans le magasin du
        // navigateur — d'où un poids de vérification faible, pas un échec.
        const chaine = socket.getPeerCertificates
          ? socket.getPeerCertificates()
          : [];

        const x509 = brut && brut.raw ? new crypto.X509Certificate(brut.raw) : null;

        const altNames = lireAltNames(x509 && x509.subjectAltName);

        /*
          Le certificat couvre-t-il le nom demandé ?

          `checkHost` rejoue la correspondance de la RFC 6125 : jokers de
          domaine, ports, IPv6. Le faire ici plutôt que lire `subject` évite le
          piège classique — un certificat émis pour un nom qui n'est plus
          celui du site, et que le navigateur refuse alors que l'expiration
          est encore dans trois mois.
        */
        let couvreHote = null;
        if (x509) {
          try {
            couvreHote = x509.checkHost(hostname);
          } catch {
            couvreHote = null;
          }
        }

        terminer({
          ok: true,
          protocole,
          chiffrement: chiffrement
            ? { nom: chiffrement.name, version: chiffrement.version }
            : null,          autorise: !erreurs,
          erreurVerification: erreurs ? String(erreurs) : null,

          sujet: x509 ? x509.subject : null,
          emetteur: x509 ? x509.issuer : null,
          valableDu: x509 ? x509.validFrom : null,
          valideAu: x509 ? x509.validTo : null,
          joursRestants: x509 ? joursAvant(x509.validTo) : null,
          altNames,
          couvreHote,
          profondeurChaine: chaine.length,
          empreinte: x509 ? x509.fingerprint256 : null,
        });
      } catch (err) {
        terminer({ ok: false, erreur: err && err.code ? err.code : 'TLS_PARSE' });
      }
    });
  });
}

/** Nombre de jours entiers avant une date. Négatif si elle est passée. */
function joursAvant(dateIso) {
  const echeance = new Date(dateIso).getTime();
  if (Number.isNaN(echeance)) return null;
  return Math.floor((echeance - Date.now()) / 86400000);
}

module.exports = { analyserTls, lireAltNames, joursAvant, estNomHote, TIMEOUT_MS };
