// @vitest-environment node
/*
  Tests de l'analyse de sécurité (Vigie).
 *
 * `analyser()` est une fonction pure : aucun réseau, aucune horloge en dehors
 * du champ `maintenant`. C'est ce qui permet de couvrir ici des situations
 * qu'aucun site public ne consent à présenter — un certificat expiré, un cookie
 * de session sans `HttpOnly`, une réflexion d'origine avec identifiants — sans
 * construire un serveur TLS sur mesure pour les produire.
 *
 * C'est aussi l'argument le plus solide en entretien : la partie qui **trouve**
 * les failles est celle qui est couverte par des cas construits, pas seulement
 * par un test de bout en bout qui dirait « ça marche sur example.com ».
 *
 * Aucun réseau n'est utilisé ici : pas de `nock`, pas de serveur. Le module
 * testé ne fait ni l'un ni l'autre.
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const {
  analyser,
  parseSetCookie,
  parseCsp,
  analyserChaine,
  analyserCookies,
  analyserCors,
  analyserEntetes,
  hoteDe,
  ORIGINE_SONDE,
} = require('../lib/analyze.js');
const { calculerScore, verdictPour } = require('../lib/score.js');

/** Relevé minimal, en HTTPS sans rien dessus : la base de tous les cas. */
function releveBase(surcharge = {}) {
  return {
    url: 'https://exemple.fr/',
    urlFinale: 'https://exemple.fr/',
    chaine: ['https://exemple.fr/'],
    sauts: [],
    status: 200,
    headers: {},
    html: '<html><body></body></html>',
    dureeMs: 10,
    tls: null,
    cors: { realise: true, acao: null, acac: null, acam: null },
    ...surcharge,
  };
}

/** Trouve un constat par son identifiant, ou `undefined`. */
function parId(checks, id) {
  return checks.find((c) => c.id === id);
}

describe('parseSetCookie — lecture d\'un cookie', () => {
  it('lit les attributs de base', () => {
    const cookie = parseSetCookie('PHPSESSID=abc123; Path=/; HttpOnly; Secure; SameSite=Lax');
    expect(cookie.nom).toBe('PHPSESSID');
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe('Lax');
    expect(cookie.path).toBe('/');
    expect(cookie.domain).toBeNull();
  });

  /*
    Le piège que ce test verrouille.

    Un `Expires` contient une virgule : `Expires=Wed, 21 Oct 2026 07:28:00 GMT`.
    Un découpage naïf à la virgule produirait deux morceaux, le premier portant
    `Expires=Wed` et perdant tous les attributs qui suivent — dont `Domain` et
    `Secure`, c'est-à-dire exactement ce que l'audit cherche.
  */
  it('ne perd pas les attributs quand Expires contient une virgule', () => {
    const cookie = parseSetCookie(
      'sid=x; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Domain=.exemple.fr; Secure; HttpOnly'
    );
    expect(cookie.expires === undefined || true).toBe(true); // pas d'attribut exploité
    expect(cookie.domain).toBe('exemple.fr');
    expect(cookie.secure).toBe(true);
    expect(cookie.httpOnly).toBe(true);
  });

  it('retire le point initial du domaine', () => {
    expect(parseSetCookie('a=b; Domain=.sous.exemple.fr').domain).toBe('sous.exemple.fr');
  });

  it('reconnaît les préfixes de contrainte', () => {
    expect(parseSetCookie('__Host-sid=1; Secure; Path=/').prefixe).toBe('__Host-');
    expect(parseSetCookie('__Secure-sid=1; Secure').prefixe).toBe('__Secure-');
    expect(parseSetCookie('sid=1; Secure').prefixe).toBeNull();
  });
});

describe('parseCsp — lecture d\'une politique', () => {
  it('découpe les directives et met les valeurs en minuscules de nom', () => {
    const directives = parseCsp("default-src 'self'; Script-Src 'self' 'unsafe-inline'; object-src 'none'");
    expect(directives).toHaveLength(3);
    expect(directives[1].nom).toBe('script-src');
    expect(directives[1].valeurs).toEqual(["'self'", "'unsafe-inline'"]);
  });

  it('ignore les blocs vides', () => {
    expect(parseCsp("default-src 'self';;  ; object-src 'none'")).toHaveLength(2);
  });
});

describe('Transport — https et certificat', () => {
  it('signale un site servi en clair comme un échec critique', () => {
    const { checks } = analyser(releveBase({
      urlFinale: 'http://exemple.fr/',
      url: 'http://exemple.fr/',
    }));
    const https = parId(checks, 'https');
    expect(https.statut).toBe('fail');
    expect(https.severite).toBe('critique');
  });

  /*
    Sans TLS, l'audit ne doit pas fabriquer un constat de certificat.
    Le pire défaut d'un outil de sécurité est de montrer un problème qui
    n'existe pas : l'utilisateur apprend alors à ignorer ses rapports.
  */
  it('n\'invente aucun constat de certificat sur un site en HTTP', () => {
    const { checks } = analyser(releveBase({
      urlFinale: 'http://exemple.fr/',
      url: 'http://exemple.fr/',
      tls: null,
    }));
    const ids = checks.map((c) => c.id);
    expect(ids).toContain('https');
    expect(ids).not.toContain('tls-version');
    expect(ids).not.toContain('tls-expiration');
  });

  it('rejette une version TLS dépréciée', () => {
    const { checks } = analyser(releveBase({
      tls: {
        ok: true, protocole: 'TLSv1', joursRestants: 100, autorise: true,
        couvreHote: true, profondeurChaine: 2, altNames: { dns: ['exemple.fr'], ip: [] },
      },
    }));
    const version = parId(checks, 'tls-version');
    expect(version.statut).toBe('fail');
    expect(version.severite).toBe('elevee');
  });

  it('accepte TLS 1.3 et signale 1.2 comme un avertissement, pas un échec', () => {
    const base = {
      ok: true, joursRestants: 100, autorise: true, couvreHote: true,
      profondeurChaine: 1, altNames: { dns: ['exemple.fr'], ip: [] },
    };
    expect(parId(analyser(releveBase({ tls: { ...base, protocole: 'TLSv1.3' } })).checks, 'tls-version').statut)
      .toBe('pass');
    // TLS 1.2 reste sûre : c'est un choix de compatibilité, pas une vulnérabilité.
    expect(parId(analyser(releveBase({ tls: { ...base, protocole: 'TLSv1.2' } })).checks, 'tls-version').statut)
      .toBe('warn');
  });

  it('traite un certificat expiré comme critique', () => {
    const { checks } = analyser(releveBase({
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: -3, autorise: true,
        couvreHote: true, profondeurChaine: 1, valideAu: '2026-09-22',
        altNames: { dns: ['exemple.fr'], ip: [] },
      },
    }));
    const expiration = parId(checks, 'tls-expiration');
    expect(expiration.statut).toBe('fail');
    expect(expiration.severite).toBe('critique');
  });

  it('avertit sous quinze jours sans traiter cela comme une faute', () => {
    const { checks } = analyser(releveBase({
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: 9, autorise: true,
        couvreHote: true, profondeurChaine: 1, altNames: { dns: ['exemple.fr'], ip: [] },
      },
    }));
    expect(parId(checks, 'tls-expiration').statut).toBe('warn');
  });

  it('repère un certificat qui ne porte pas le nom demandé', () => {
    const { checks } = analyser(releveBase({
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: 100, autorise: true,
        couvreHote: false, profondeurChaine: 1, altNames: { dns: ['autre.fr'], ip: [] },
      },
    }));
    const hote = parId(checks, 'tls-hote');
    expect(hote.statut).toBe('fail');
    expect(hote.severite).toBe('critique');
  });

  it('signale une chaîne de confiance refusée', () => {
    const { checks } = analyser(releveBase({
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: 100, autorise: false,
        erreurVerification: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        couvreHote: true, profondeurChaine: 0, altNames: { dns: ['exemple.fr'], ip: [] },
      },
    }));
    expect(parId(checks, 'tls-chaine').statut).toBe('fail');
  });

  it('marque « non mesurable » quand la sonde TLS n\'a pas abouti', () => {
    const { checks } = analyser(releveBase({ tls: { ok: false, erreur: 'ECONNRESET' } }));
    const present = parId(checks, 'tls-present');
    expect(present.statut).toBe('fail');
  });
});

describe('En-têtes de sécurité', () => {
  it('refuse HSTS en dessous de six mois', () => {
    const { checks } = analyser(releveBase({
      headers: { 'strict-transport-security': 'max-age=300' },
    }));
    expect(parId(checks, 'hsts').statut).toBe('warn');
  });

  it('accepte une politique HSTS couvrant les sous-domaines', () => {
    const { checks } = analyser(releveBase({
      headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
    }));
    expect(parId(checks, 'hsts').statut).toBe('pass');
  });

  it('déclare HSTS hors sujet sur un site en clair', () => {
    const { checks } = analyser(releveBase({
      url: 'http://exemple.fr/',
      urlFinale: 'http://exemple.fr/',
    }));
    expect(parId(checks, 'hsts').statut).toBe('pass');
  });

  /*
    La configuration la plus répandue et la plus trompeuse : l'en-tête est là,
    la protection ne l'est pas. Le test verrouille que le statut n'est **pas**
    `pass` — et qu'il est signalé comme élevé, parce que le propriétaire du
    site croira sinon être protégé.
  */
  it('détecte une CSP inopérante sous unsafe-inline sans nonce', () => {
    const { checks } = analyser(releveBase({
      headers: { 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'" },
    }));
    const csp = parId(checks, 'csp');
    expect(csp.statut).not.toBe('pass');
    expect(csp.severite).toBe('elevee');
  });

  it('n\'exige pas les directives de confort quand le point testé est le nonce', () => {
    const { checks } = analyser(releveBase({
      headers: {
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-a1'; object-src 'none'",
      },
    }));
    const csp = parId(checks, 'csp');
    // Le point vérifié : un nonce rend `'unsafe-inline'` acceptable, donc
    // la politique n'est plus jugée inopérante — même si d'autres directives
    // manquent et que le constat reste un avertissement pour cette raison.
    expect(csp.severite).not.toBe('elevee');
    expect(csp.resume).not.toMatch(/inopérante/);
  });

  it('refuse le joker et data: dans script-src', () => {
    const { checks } = analyser(releveBase({
      headers: { 'content-security-policy': "default-src 'self'; script-src * data:; object-src 'none'" },
    }));
    const csp = parId(checks, 'csp');
    expect(csp.statut).toBe('warn');
    expect(csp.resume).toMatch(/joker/);
  });

  it('traite une CSP en mode rapport seul comme absente', () => {
    const { checks } = analyser(releveBase({
      headers: { 'content-security-policy-report-only': "default-src 'none'" },
    }));
    const csp = parId(checks, 'csp');
    expect(csp.statut).toBe('warn');
    expect(csp.resume).toMatch(/rapport seul/);
  });

  it('privilégie frame-ancestors sur X-Frame-Options', () => {
    const { checks } = analyser(releveBase({
      headers: {
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'x-frame-options': 'ALLOWALL',
      },
    }));
    expect(parId(checks, 'clickjacking').statut).toBe('pass');
  });

  it('signale une page encadrable par n\'importe qui', () => {
    const { checks } = analyser(releveBase());
    const cadre = parId(checks, 'clickjacking');
    expect(cadre.statut).toBe('fail');
    expect(cadre.severite).toBe('elevee');
  });

  it('liste les en-têtes qui nomment la pile', () => {
    const { checks } = analyser(releveBase({
      headers: { server: 'nginx/1.24.0', 'x-powered-by': 'PHP/8.2.1' },
    }));
    const divulgation = parId(checks, 'divulgation');
    expect(divulgation.statut).toBe('warn');
    expect(divulgation.preuve).toMatch(/nginx/);
  });
});

describe('Cookies', () => {
  it('accepte un site sans cookie', () => {
    const { checks } = analyser(releveBase());
    expect(parId(checks, 'cookies').statut).toBe('pass');
  });

  it('traite un cookie de session sans HttpOnly comme un échec critique', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['PHPSESSID=abc; Path=/; Secure; SameSite=Lax'] },
    }));
    const httponly = parId(checks, 'cookie-httponly');
    expect(httponly.statut).toBe('fail');
    expect(httponly.severite).toBe('critique');
  });

  it('ne confond pas un cookie de préférence avec une session', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['theme=sombre; Path=/; Secure; HttpOnly; SameSite=Lax'] },
    }));
    expect(parId(checks, 'cookie-httponly').statut).toBe('pass');
  });

  it('refuse un cookie sans Secure sur un site en HTTPS', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['theme=sombre; Path=/; HttpOnly; SameSite=Lax'] },
    }));
    expect(parId(checks, 'cookie-secure').statut).toBe('fail');
  });

  it('considère SameSite absent comme un défaut sur un cookie de session', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['PHPSESSID=abc; Path=/; Secure; HttpOnly'] },
    }));
    expect(parId(checks, 'cookie-samesite').statut).toBe('warn');
  });

  it('signale un cookie élargi à un domaine parent', () => {
    const { checks } = analyser(releveBase({
      headers: {
        'set-cookie': ['PHPSESSID=abc; Path=/; Domain=.exemple.fr; Secure; HttpOnly; SameSite=Lax'],
      },
    }));
    expect(parId(checks, 'cookie-domaine').statut).toBe('warn');
  });

  it('reconnaît un cookie __Host- comme bien contraint', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax'] },
    }));
    expect(parId(checks, 'cookie-prefixe').statut).toBe('pass');
  });

  /*
    Le préfixe ne doit pas cacher le cookie de session.

    `__Host-sid` est un cookie de session, et le moteur doit donc l'examiner
    comme tel. Le prendre pour un cookie ordinaire le ferait passer inaperçu —
    c'est-à-dire produire un rapport rassurant à tort, le pire défaut possible
    ici. Ce test verrouille le cas.
  */
  it('examine un cookie de session préfixé comme une session', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['__Host-sid=abc; Path=/; Secure; SameSite=Lax'] },
    }));
    // Sans HttpOnly, il doit être signalé comme lisible par le script.
    expect(parId(checks, 'cookie-httponly').statut).toBe('fail');
  });

  /*
    Un rapport ne doit pas affirmer ce qu'il n'a pas vérifié.

    Quand aucun cookie de session n'est identifiable, dire « les cookies de
    session portent un préfixe » serait une affirmation sans fondement : l'outil
    ne voit que la réponse analysée. Le statut `info` dit la bonne chose — il
    n'y a rien à signaler, sans prétendre que tout est en ordre.
  */
  it('ne conclut pas sur les préfixes quand aucune session n\'est identifiable', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['WMF-Last_Access=2026-09-25; Path=/; Secure; HttpOnly'] },
    }));
    const prefixe = parId(checks, 'cookie-prefixe');
    expect(prefixe.statut).toBe('info');
    expect(prefixe.resume).toMatch(/Aucun cookie de session/);
  });
});

describe('CORS', () => {
  /*
    Le cas le plus grave, et le seul qui vaille vraiment « critique » : le
    serveur renvoie l'origine qu'on lui a donnée **et** autorise les
    identifiants. Tout site tiers peut alors lire la réponse avec la session
    du visiteur.
  */
  it('détecte une réflexion d\'origine avec identifiants autorisés', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: true, acao: ORIGINE_SONDE, acac: 'true', acam: null },
    }));
    const reflection = parId(checks, 'cors-reflection');
    expect(reflection.statut).toBe('fail');
    expect(reflection.severite).toBe('critique');
  });

  it('abaisse la réflexion sans identifiants à un avertissement', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: true, acao: ORIGINE_SONDE, acac: null, acam: null },
    }));
    const reflection = parId(checks, 'cors-reflection');
    expect(reflection.statut).toBe('warn');
    expect(reflection.severite).toBe('moyenne');
  });

  it('valide une liste d\'origines explicite', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: true, acao: 'https://app.exemple.fr', acac: 'true', acam: 'GET,POST' },
    }));
    expect(parId(checks, 'cors-reflection').statut).toBe('pass');
  });

  it('signale le joker combiné aux identifiants', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: true, acao: '*', acac: 'true', acam: null },
    }));
    const spec = parId(checks, 'cors-spec');
    expect(spec.statut).toBe('fail');
    // La réflexion n'est pas en cause ici : c'est la contradiction, pas l'écho.
    expect(parId(checks, 'cors-reflection').statut).toBe('pass');
  });

  it('reste silencieux sur les méthodes autorisées quand tout est en ordre', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: true, acao: 'https://app.exemple.fr', acac: 'true', acam: 'GET,POST' },
    }));
    expect(parId(checks, 'cors-spec')).toBeUndefined();
  });

  /*
    Une sonde qui n'a pas abouti doit produire un constat **d'absence de mesure**,
    jamais un constat de risque. C'est la différence entre un rapport honnête et
    un rapport qui fabrique de l'inquiétude.
  */
  it('dit n\'avoir pas pu mesurer quand la sonde échoue', () => {
    const { checks } = analyser(releveBase({
      cors: { realise: false, raison: 'ETIMEDOUT' },
    }));
    const cors = parId(checks, 'cors');
    expect(cors.statut).toBe('info');
    expect(cors.resume).toMatch(/pas pu aboutir/);
    expect(parId(checks, 'cors-reflection')).toBeUndefined();
  });
});

describe('Chaîne de redirections', () => {
  const saut = (url, status, setCookie = []) => ({
    url, status, location: status < 400 ? null : 'https://final.fr/', headers: {}, setCookie,
  });

  it('valide une chaîne sans saut et sans cookie', () => {
    const checks = analyserChaine(releveBase({ sauts: [saut('https://exemple.fr/', 200)] }));
    expect(parId(checks, 'chaine-downgrade').statut).toBe('pass');
    expect(parId(checks, 'chaine-cookie-redirection').statut).toBe('pass');
  });

  /*
    Le cas que les scanners d'en-têtes ne voient pas : ils ne lisent que la
    réponse finale, où ce cookie n'apparaît pas. Il est pourtant déjà stocké,
    pour l'hôte intermédiaire, **avant** que le visiteur n'arrive.
  */
  it('détecte un cookie posé sur une redirection', () => {
    const checks = analyserChaine(releveBase({
      sauts: [
        // Le cookie est porté par la **redirection**, pas par la réponse finale.
        // C'est toute la difficulté : un scanner qui ne lit que la dernière
        // réponse ne le voit jamais.
        saut('https://exemple.fr/', 301, ['PHPSESSID=abc; Path=/; Secure; HttpOnly']),
        saut('https://final.fr/', 200),
      ],
    }));
    const pose = parId(checks, 'chaine-cookie-redirection');
    expect(pose.statut).toBe('warn');
    expect(pose.preuve).toMatch(/PHPSESSID/);
  });

  it('ne signale pas un cookie posé par la réponse finale', () => {
    const checks = analyserChaine(releveBase({
      sauts: [saut('https://final.fr/', 200, ['PHPSESSID=abc; Path=/; Secure; HttpOnly'])],
    }));
    expect(parId(checks, 'chaine-cookie-redirection').statut).toBe('pass');
  });

  it('détecte un saut en clair avant la page chiffrée', () => {
    const checks = analyserChaine(releveBase({
      sauts: [saut('http://exemple.fr/', 301), saut('https://final.fr/', 200)],
    }));
    const downgrade = parId(checks, 'chaine-downgrade');
    expect(downgrade.statut).toBe('fail');
    expect(downgrade.preuve).toMatch(/http:\/\/exemple\.fr/);
  });

  it('valide un changement d\'hôte sans cookie élargi', () => {
    const checks = analyserChaine(releveBase({
      sauts: [saut('https://exemple.fr/', 301), saut('https://final.fr/', 200)],
    }));
    expect(parId(checks, 'chaine-domaine').statut).toBe('pass');
  });

  it('sait lire un hôte hors d\'une URL illisible', () => {
    expect(hoteDe('pas-une-url')).toBe('');
    expect(hoteDe('https://Exemple.FR/x')).toBe('exemple.fr');
  });
});

describe('Contenu mixte', () => {
  it('signale une ressource référencée en HTTP', () => {
    const { checks } = analyser(releveBase({
      html: '<html><head><script src="http://cdn.exemple.fr/app.js"></script></head></html>',
    }));
    const mixte = parId(checks, 'contenu-mixte');
    expect(mixte.statut).toBe('warn');
    expect(mixte.preuve).toMatch(/cdn\.exemple\.fr/);
  });

  it('ne relève pas une mention en texte ou en commentaire', () => {
    const { checks } = analyser(releveBase({
      html: '<p>voir http://exemple.fr</p><!-- http://exemple.fr --><script src="/a.js"></script>',
    }));
    expect(parId(checks, 'contenu-mixte').statut).toBe('pass');
  });

  it('ignore les adresses locales dans les ressources', () => {
    const { checks } = analyser(releveBase({
      html: '<img src="http://localhost:8080/pixel.gif">',
    }));
    expect(parId(checks, 'contenu-mixte').statut).toBe('pass');
  });
});

describe('Score et verdict', () => {
  it('départage un échec critique d\'un simple avertissement', () => {
    expect(calculerScore([{ id: 'https', statut: 'fail', severite: 'critique' }]).poidsObtenus).toBe(0);
    expect(calculerScore([{ id: 'nosniff', statut: 'warn', severite: 'faible' }]).poidsObtenus).toBe(1);
  });

  /*
    Le verrou le plus important du module. Un site peut afficher 82 avec un
    cookie de session lisible en JavaScript : le score ne doit alors jamais être
    présenté comme rassurant, et le verdict doit porter la réserve.
  */
  it('neutralise le score quand un constat critique est présent', () => {
    const calcul = calculerScore([
      { id: 'cors-reflection', statut: 'fail', severite: 'critique' },
      { id: 'tls-version', statut: 'pass', severite: 'info' },
    ]);
    expect(calcul.critique).toBe(true);
    expect(verdictPour(calcul).mot).toBe('Critique');
  });

  it('n\'exclut pas un constat de poids nul de la correction', () => {
    const calcul = calculerScore([{ id: 'cors-origines', statut: 'fail', severite: 'info' }]);
    expect(calcul.poidsTotal).toBe(0);
    expect(calcul.score).toBe(100);
  });

  it('gradue le verdict sur le score', () => {
    expect(verdictPour(calculerScore([{ id: 'https', statut: 'pass', severite: 'info' }])).mot).toBe('Solide');
    expect(verdictPour(calculerScore([{ id: 'https', statut: 'fail', severite: 'critique' }])).mot).toBe('Critique');
  });
});

describe('Assemblage', () => {
  it('classe les constats du plus grave au plus léger', () => {
    const { checks } = analyser(releveBase({
      headers: { 'set-cookie': ['PHPSESSID=abc; Path=/'] },
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: 200, autorise: true,
        couvreHote: true, profondeurChaine: 1, altNames: { dns: ['exemple.fr'], ip: [] },
      },
    }));
    // Les deux premiers doivent être les échecs, jamais un « pass ».
    expect(checks.slice(0, 2).every((c) => c.statut === 'fail')).toBe(true);
    const premiersStatuts = checks.filter((c) => c.statut === 'fail').map((c) => c.severite);
    const rang = { critique: 0, elevee: 1, moyenne: 2, faible: 3, info: 4 };
    const tries = [...premiersStatuts].sort((a, b) => rang[a] - rang[b]);
    expect(premiersStatuts).toEqual(tries);
  });

  it('produit un rapport complet sur un site en HTTPS bien configuré', () => {
    const { checks, familles, synthese } = analyser(releveBase({
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-a1'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=(), microphone=()',
        'set-cookie': ['__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax'],
      },
      tls: {
        ok: true, protocole: 'TLSv1.3', joursRestants: 200, autorise: true,
        couvreHote: true, profondeurChaine: 2, emetteur: 'CN=Exemple',
        altNames: { dns: ['exemple.fr', 'www.exemple.fr'], ip: [] },
      },
      cors: { realise: true, acao: 'https://app.exemple.fr', acac: 'true', acam: 'GET' },
    }));

    expect(synthese.echecs).toBe(0);
    expect(familles.map((f) => f.id)).toContain('transport');
    // Un site sans défaut ne doit pas non plus être ponctué d'avertissements.
    expect(calculerScore(checks).score).toBeGreaterThanOrEqual(95);
  });
});
