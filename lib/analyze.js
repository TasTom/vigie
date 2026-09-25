/**
 * Vigie — moteur d'analyse de la sécurité d'un site, en configuration.
 *
 * ## Ce que cet outil fait, et ce qu'il ne fait pas
 *
 * Il vérifie une **liste nommée et finie** de réglages : TLS, en-têtes de
 * sécurité, drapeaux de cookies, politique CORS, et ce qui se passe sur chaque
 * saut de redirection. Il ne cherche ni injection SQL, ni XSS, ni faille
 * d'authentification : ces familles-là exigent d'envoyer des charges utiles
 * et de comprendre l'application, pas de lire ses en-têtes. Un rapport qui
 * laisserait croire le contraire serait un rapport faux, donc la page
 * d'accueil du rapport le dit explicitement.
 *
 * ## Ce qui rend cet outil différent d'un scanner d'en-têtes
 *
 * La plupart d'entre eux ne regardent que **la réponse finale**. Trois constats
 * ici n'existent qu'en regardant **toute la chaîne**, et disparaissent
 * entièrement d'un rapport qui s'arrête au dernier saut :
 *
 *  1. un `Set-Cookie` posé sur une **redirection** — le cookie est planté avant
 *     que le visiteur arrive quelque part ;
 *  2. une réponse en **`http`** précède le `https` — le premier saut est en
 *     clair, et la feuille de style HSTS ne rattrape pas ce qui est déjà passé ;
 *  3. un cookie posé avec un **domaine parent** au passage — il survit au
 *     changement d'hôte et suit le visiteur chez le suivant.
 *
 * ## Le test CORS
 *
 * Une réflexion d'origine ne se voit pas si on ne demande pas une origine : un
 * serveur qui n'a rien à cacher répond `*` à une requête sans `Origin`. Le
 * relevé envoie donc une **seconde** requête portant une origine synthétique
 * (`https://vigie-probe.invalid`, dans un TLD réservé par la RFC 2606, donc
 * résoluble par personne) et compare. C'est ce qui sépare « configuré
 * correctement » de « lisible par n'importe quel site ».
 *
 * ## Forme des entrées et des sorties
 *
 * `analyser()` est une fonction **pure** : elle ne fait ni réseau ni horloge
 *et ne dépend que d'un objet `releve` et du champ `maintenant`. C'est ce qui la
 * rend testable sans serveur, et c'est la raison pour laquelle les tests de
 * `analyze.test.js` peuvent couvrir TLS expiré, cookie sans `SameSite`,
 * réflexion CORS et chaîne croisée sans jamais ouvrir une socket.
 */

/* -------------------------------------------------------------------------- */
/* Lecture des en-têtes                                                        */
/* -------------------------------------------------------------------------- */

/** En-tête par nom, insensible à la casse. */
function entete(headers, nom) {
  if (!headers) return undefined;
  const cible = nom.toLowerCase();
  for (const cle of Object.keys(headers)) {
    if (cle.toLowerCase() === cible) return headers[cle];
  }
  return undefined;
}

/** `set-cookie` est toujours un tableau sous Node ; un littéral en tests aussi. */
function listeSetCookie(headers) {
  const brut = entete(headers, 'set-cookie');
  if (!brut) return [];
  return Array.isArray(brut) ? brut : [brut];
}

/**
 * Décompose un `Set-Cookie` en ses attributs.
 *
 * Un attribut `Expires` contient lui-même une virgule, d'où l'analyse par
 * points-virgules — un découpage naïf à la virgule couperait le cookie en deux
 * et perdrait le domaine, qui est justement ce qu'on cherche ici.
 */
function parseSetCookie(brut) {
  const morceaux = String(brut).split(';');
  const paire = morceaux.shift() || '';
  const signe = paire.indexOf('=');
  const nom = (signe === -1 ? paire : paire.slice(0, signe)).trim();

  const cookie = {
    nom,
    brut: String(brut),
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    maxAge: null,
    prefixe: null,
  };

  for (const morceau of morceaux) {
    const egal = morceau.indexOf('=');
    const cle = (egal === -1 ? morceau : morceau.slice(0, egal)).trim().toLowerCase();
    const valeur = egal === -1 ? '' : morceau.slice(egal + 1).trim();

    if (cle === 'secure') cookie.secure = true;
    else if (cle === 'httponly') cookie.httpOnly = true;
    else if (cle === 'samesite') cookie.sameSite = valeur || null;
    else if (cle === 'domain') cookie.domain = valeur.replace(/^\./, '').toLowerCase() || null;
    else if (cle === 'path') cookie.path = valeur || null;
    else if (cle === 'max-age') cookie.maxAge = Number(valeur);
  }

  if (nom.startsWith('__Host-')) cookie.prefixe = '__Host-';
  else if (nom.startsWith('__Secure-')) cookie.prefixe = '__Secure-';

  return cookie;
}

/** Domaines dont le nom évoque une session plutôt qu'une préférence. */
const NOMS_SESSION = /^(phpsessid|jsessionid|asp\.net_sessionid|sess|session|sid|token|jwt|auth|.*session.*|.*token.*)$/i;

/**
 * Un cookie est-il une session ?
 *
 * Le préfixe de contrainte est retiré avant comparaison : `__Host-sid` est
 * bien un cookie de session, et la comparaison sur le nom entier le ferait
 * passer pour un cookie ordinaire — donc pour un cookie qu'on n'a pas à
 * examiner. C'est le genre d'erreur qui rend un rapport rassurant à tort.
 */
function estCookieSession(nom) {
  const nu = String(nom || '').replace(/^__(?:Host|Secure)-/i, '');
  return NOMS_SESSION.test(nu);
}

/* -------------------------------------------------------------------------- */
/* Construction des constats                                                   */
/* -------------------------------------------------------------------------- */

const FAMILLES = [
  { id: 'transport', nom: 'Transport et certificat' },
  { id: 'entetes', nom: "En-têtes de sécurité" },
  { id: 'cookies', nom: 'Cookies' },
  { id: 'cors', nom: 'CORS' },
  { id: 'chaine', nom: 'Chaîne de redirections' },
];

/** Sévérités, de la plus grave à la plus légère. */
const SEVERITES = ['critique', 'elevee', 'moyenne', 'faible', 'info'];

function constat(entree) {
  return {
    famille: 'entetes',
    statut: 'warn',
    severite: 'moyenne',
    resume: '',
    detail: '',
    preuve: null,
    correction: null,
    ...entree,
  };
}

/** Trier une famille par gravité : ce qui se répare d'abord vient en premier. */
const RANG_STATUT = { fail: 0, warn: 1, pass: 2 };
const RANG_SEVERITE = { critique: 0, elevee: 1, moyenne: 2, faible: 3, info: 4 };

function parGravite(a, b) {
  const st = RANG_STATUT[a.statut] - RANG_STATUT[b.statut];
  if (st !== 0) return st;
  return RANG_SEVERITE[a.severite] - RANG_SEVERITE[b.severite];
}

/* -------------------------------------------------------------------------- */
/* Transport et certificat                                                     */
/* -------------------------------------------------------------------------- */

function analyserTransport(releve) {
  const out = [];
  const finale = new URL(releve.urlFinale);
  const enHttps = finale.protocol === 'https:';
  const tls = releve.tls;

  out.push(constat({
    id: 'https',
    famille: 'transport',
    titre: 'Le site est servi en HTTPS',
    statut: enHttps ? 'pass' : 'fail',
    severite: enHttps ? 'info' : 'critique',
    resume: enHttps
      ? 'La réponse finale arrive en HTTPS.'
      : 'La réponse finale arrive en HTTP, sans aucun chiffrement.',
    detail: enHttps
      ? 'Le trafic est chiffré. C\'est le prérequis de tout le reste : un en-tête de sécurité ne protège que ce qu\'il ne peut pas voir arriver en clair.'
      : 'Tout ce qui circule — identifiants de session, cookies, formulaires — est lisible sur le trajet. Aucun en-tête ne rattrape cela : le cookie peut déjà avoir été intercepté avant d\'arriver.',
    preuve: finale.protocol,
    correction: 'Servir la même page en HTTPS et rediriger le HTTP avec un 301 permanent.',
  }));

  if (!enHttps) {
    // Sans TLS, interroger la connexion n'aurait aucun sens : on ne prétend pas
    // avoir regardé un certificat qu'on n'a pas pu atteindre.
    return out;
  }

  if (!tls) {
    out.push(constat({
      id: 'tls-present',
      famille: 'transport',
      titre: 'La connexion TLS a pu être ouverte',
      statut: 'warn',
      severite: 'moyenne',
      resume: 'La connexion chiffrée n\'a pas pu être inspectée.',
      detail: 'L\'analyse du certificat a échoué ou a expiré avant son terme. Le reste du rapport porte sur les en-têtes uniquement, et cette partie mérite d\'être refaite.',
      preuve: null,
      correction: 'Vérifier que le port 443 est ouvert et le certificat servi.',
    }));
    return out;
  }

  if (!tls.ok) {
    out.push(constat({
      id: 'tls-present',
      famille: 'transport',
      titre: 'La connexion TLS a pu être ouverte',
      statut: tls.bloque ? 'pass' : 'fail',
      severite: tls.bloque ? 'info' : 'elevee',
      resume: tls.bloque
        ? 'Adresse hors du réseau public : non analysable, et c\'est le comportement attendu.'
        : `La connexion chiffrée a échoué (${tls.erreur}).`,
      detail: tls.bloque
        ? 'L\'outil refuse par construction les adresses internes et.loopback et de métadonnées : il ne s\'analyse pas lui-même.'
        : 'Aucun échange TLS n\'a pu aboutir sur ce port. Le site est soit indisponible en HTTPS, soit configuré pour refuser ce type de client.',
      preuve: tls.erreur || null,
      correction: tls.bloque ? null : 'Contrôler le certificat et la version de TLS proposée par le serveur.',
    }));
    return out;
  }

  /* --- Version négociée ---------------------------------------------------
     RFC 8996 (2021) : TLS 1.0 et 1.1 sont dépréciés, TLS 1.2 est le minimum
     acceptable, TLS 1.3 est l'état de l'art. On ne traite pas 1.2 comme une
     faute — c'est un choix de compatibilité, pas une vulnérabilité. */
  const protocole = String(tls.protocole || '');
  const versionOk = protocole === 'TLSv1.3';
  /*
    `TLSv1` sans suffixe est bien TLS 1.0, et c'est exactement la chaîne que
    produit Node pour un serveur qui n'offre que cela. L'expression doit donc
    couvrir le cas nu aussi — sinon le pire protocole negotiate passe pour un
    simple avertissement, ce qui est le défaut que ce test verrouille.
  */
  const versionObsolete = /^TLSv1(\.0|\.1)?$/.test(protocole);

  out.push(constat({
    id: 'tls-version',
    famille: 'transport',
    titre: 'Version de TLS proposée',
    statut: versionObsolete ? 'fail' : versionOk ? 'pass' : 'warn',
    severite: versionObsolete ? 'elevee' : versionOk ? 'info' : 'faible',
    resume: versionObsolete
      ? `${protocole} est déprécié depuis 2021 (RFC 8996).`
      : versionOk
        ? 'TLS 1.3, l\'état de l\'art.'
        : `${protocole} : acceptable, mais pas l'état de l'art.`,
    detail: versionObsolete
      ? 'La version proposée est retirée des recommandations. Elle est connue pour être cassable par des implémentations tierces, et certains navigateurs la refusent déjà.'
      : versionOk
        ? 'Session résumée, chiffrement éphémère et suppression de la cryptographie statique : la meilleure configuration disponible aujourd\'hui.'
        : 'TLS 1.2 reste sûre si la suite de chiffrement est solide. Passer en 1.3 apporte moins de trafic réexécuté et supprime certains algorithmes.',
    preuve: protocole,
    correction: versionObsolete ? 'Ne proposer que TLS 1.2 et 1.3.' : versionOk ? null : 'Activer TLS 1.3.',
  }));

  /* --- Expiration --------------------------------------------------------- */
  const jours = tls.joursRestants;
  const expire = typeof jours === 'number' && jours < 0;

  out.push(constat({
    id: 'tls-expiration',
    famille: 'transport',
    titre: 'Le certificat est valide',
    statut: expire ? 'fail' : typeof jours === 'number' && jours < 15 ? 'warn' : 'pass',
    severite: expire ? 'critique' : typeof jours === 'number' && jours < 15 ? 'elevee' : 'info',
    resume: expire
      ? `Certificat expiré depuis ${Math.abs(jours)} jour(s).`
      : typeof jours === 'number'
        ? `Il reste ${jours} jour(s) avant expiration.`
        : 'Date d\'expiration non lisible.',
    detail: expire
      ? 'Un certificat expiré produit un avertissement dans le navigateur, et dans certains cas un blocage. Passé un certain délai, l\'avertissement habitue : les visiteurs apprennent à cliquer sur « Continuer quand même », et l\'avertissement ne protège plus rien.'
      : typeof jours === 'number' && jours < 15
        ? 'Sous quinze jours, un renouvellement automatique peut prendre le temps d\'aboutir — une coupure de service caused par un oubli, pas par une attaque.'
        : 'Le certificat est dans sa période de validité.',
    preuve: tls.valideAu || null,
    correction: expire
      ? 'Renouveler le certificat et automatiser le renouvellement.'
      : 'Surveiller la date d\'expiration dans la chaîne de déploiement.',
  }));

  /* --- Correspondance avec le nom d'hôte --------------------------------- */
  out.push(constat({
    id: 'tls-hote',
    famille: 'transport',
    titre: 'Le certificat porte le bon nom',
    statut: tls.couvreHote === false ? 'fail' : 'pass',
    severite: tls.couvreHote === false ? 'critique' : 'info',
    resume: tls.couvreHote === false
      ? 'Le certificat ne couvre pas le nom demandé.'
      : 'Le certificat couvre le nom demandé.',
    detail: tls.couvreHote === false
      ? 'Le navigateur refuse la connexion sur une erreur de nom, même si le certificat n\'est pas expiré. C\'est la panne la plus fréquente après un changement de nom de domaine : le certificat renewal suit l\'ancien nom.'
      : 'La correspondance a été validée avec la règle de la RFC 6125, jokers de domaine compris.',
    preuve: (tls.altNames && tls.altNames.dns && tls.altNames.dns.join(', ')) || tls.sujet || null,
    correction: tls.couvreHote === false ? 'Émettre un certificat qui liste le nom réellement servi.' : null,
  }));

  /* --- Chaîne de confiance ------------------------------------------------ */
  if (tls.autorise === false) {
    out.push(constat({
      id: 'tls-chaine',
      famille: 'transport',
      titre: 'La chaîne de confiance est valide',
      statut: 'fail',
      severite: 'critique',
      resume: `Chaîne refusée : ${tls.erreurVerification || 'raison non précisée'}.`,
      detail: 'Le navigateur n\'a pas pu remonter jusqu\'à une autorité de confiance. Le certificat peut être valide : c\'est simplement que ce serveur ne rend pas l\'intermédiaire, et le navigateur n\'a alors pas de chemin jusqu\'à une racine de confiance.',
      preuve: tls.emetteur || null,
      correction: 'Servir la chaîne complète, intermédiaire compris.',
    }));
  } else {
    out.push(constat({
      id: 'tls-chaine',
      famille: 'transport',
      titre: 'La chaîne de confiance est valide',
      statut: 'pass',
      severite: 'info',
      resume: tls.profondeurChaine > 0
        ? `Chaîne complète, ${tls.profondeurChaine} certificat(s) intermédiaire(s).`
        : 'Aucun intermédiaire exposé.',
      detail: tls.profondeurChaine > 0
        ? 'Le serveur expose bien les certificats intermédiaires, ce qui est la règle pour un serveur public.'
        : 'Aucun intermédiaire n\'est envoyé. C\'est normal quand l\'autorité racine est déjà dans le magasin du navigateur, et dangereux quand elle ne l\'est pas — la lecture se fait sur le premier certificat présenté.',
      preuve: tls.emetteur || null,
      correction: null,
    }));
  }

  return out;
}

/* -------------------------------------------------------------------------- */
/* En-têtes                                                                    */
/* -------------------------------------------------------------------------- */

/** Découpe une CSP en directives `{ nom, valeurs[] }`. */
function parseCsp(valeur) {
  return String(valeur)
    .split(';')
    .map((bloc) => bloc.trim())
    .filter(Boolean)
    .map((bloc) => {
      const morceaux = bloc.split(/\s+/);
      return { nom: morceaux[0].toLowerCase(), valeurs: morceaux.slice(1) };
    });
}

function analyserEntetes(releve) {
  const out = [];
  const headers = releve.headers || {};
  const enHttps = new URL(releve.urlFinale).protocol === 'https:';

  /* --- HSTS --------------------------------------------------------------- */
  const hstsBrut = entete(headers, 'strict-transport-security');

  if (!enHttps) {
    out.push(constat({
      id: 'hsts',
      famille: 'entetes',
      titre: 'HSTS',
      statut: 'pass',
      severite: 'info',
      resume: 'Sans objet : le site n\'est pas en HTTPS.',
      detail: 'Strict-Transport-Security n\'a de sens que sur une origine déjà en HTTPS. Sur un site en clair, il n\'aurait aucune prise.',
      preuve: null,
      correction: null,
    }));
  } else if (!hstsBrut) {
    out.push(constat({
      id: 'hsts',
      famille: 'entetes',
      titre: 'HSTS',
      statut: 'fail',
      severite: 'elevee',
      resume: 'Aucun durcissement du transport par cet en-tête.',
      detail: 'Sans cet en-tête, la première requête de chaque visiteur peut encore partir en HTTP : un attaquant du réseau répond alors avant le serveur, et le visiteur continue de navigation. HTTPS devient alors une suggestion au lieu d\'une règle.',
      preuve: null,
      correction: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
    }));
  } else {
    const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(hstsBrut);
    const secondes = maxAge ? Number(maxAge[1]) : 0;
    const sousDomaines = /includeSubDomains/i.test(hstsBrut);
    const preload = /preload/i.test(hstsBrut);

    // Six mois est le plancher de la spécification ; les navigateurs
    // n'exigent pas moins de 18 mois pour tenter une inscription au preload.
    const tropCourt = secondes < 15552000;
    const sansInclusion = !sousDomaines;

    out.push(constat({
      id: 'hsts',
      famille: 'entetes',
      titre: 'HSTS',
      statut: tropCourt ? 'warn' : (sansInclusion ? 'warn' : 'pass'),
      severite: tropCourt || sansInclusion ? 'moyenne' : 'info',
      resume: tropCourt
        ? `max-age=${secondes} s, en dessous des six mois recommandés.`
        : `max-age=${secondes} s${sousDomaines ? ', sous-domaines inclus' : ''}${preload ? ', préchargé' : ''}.`,
      detail: tropCourt
        ? 'Un `max-age` court protège le temps qu\'un visiteur reste, puis la protection retombe. La valeur de référence est d\'une année.'
        : sansInclusion
          ? 'Sans `includeSubDomains`, un sous-domaine oublié reste accessible en HTTP. C\'est là que se cachent les forgotten subdomains : un vieux blog, un préfixe de test.'
          : 'La politique couvre l\'ensemble des sous-domaines.',
      preuve: hstsBrut,
      correction: tropCourt
        ? 'max-age=31536000 (un an) au minimum.'
        : sansInclusion ? 'Ajouter includeSubDomains.' : null,
    }));
  }

  /* --- CSP ---------------------------------------------------------------- */
  const cspBrut = entete(headers, 'content-security-policy');
  const cspReport = entete(headers, 'content-security-policy-report-only');

  if (!cspBrut) {
    out.push(constat({
      id: 'csp',
      famille: 'entetes',
      titre: 'Content-Security-Policy',
      statut: cspReport ? 'warn' : 'fail',
      severite: cspReport ? 'moyenne' : 'elevee',
      resume: cspReport
        ? 'Politique déclarée en mode « rapport seul » : elle n\'est pas appliquée.'
        : 'Aucune politique de contenu.',
      detail: cspReport
        ? 'Le mode *report-only* se contente de journaliser ce qu\'il aurait bloqué. Utile pour mesurer une politique avant de la durcir, inutile en production : tant qu\'il n\'est pas activé, le navigateur exécute tout.'
        : 'La CSP est la seule chose qui distingue le script du site de celui qu\'un tiers a réussi à y injecter. Sans elle, une seule injection de HTML suffit à exécuter du JavaScript avec les droits de l\'utilisateur — y compris pour lire ce que l\'application lui a donné.',
      preuve: cspReport || null,
      correction: cspReport
        ? 'Basculer l\'en-tête en mode bloquant une fois le rapport exploité.'
        : "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    }));
  } else {
    const directives = parseCsp(cspBrut);
    const parNom = new Map(directives.map((d) => [d.nom, d.valeurs]));

    const scriptSrc = parNom.get('script-src') || parNom.get('default-src') || [];
    const defaultSrc = parNom.get('default-src') || [];

    const inlineNonUtilisable = scriptSrc.includes("'unsafe-inline'")
      && !scriptSrc.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"));
    const evalAutorise = scriptSrc.includes("'unsafe-eval'");
    const joker = [...scriptSrc, ...defaultSrc].includes('*');
    const dataAutorise = [...scriptSrc, ...defaultSrc].includes('data:');

    const problèmes = [];
    if (inlineNonUtilisable) problèmes.push("'unsafe-inline' sans nonce ni empreinte");
    if (evalAutorise) problèmes.push("'unsafe-eval'");
    if (joker) problèmes.push('une joker (*)');
    if (dataAutorise) problèmes.push('data: autorisé');
    if (!parNom.has('object-src')) problèmes.push('object-src absent');
    if (!parNom.has('base-uri')) problèmes.push('base-uri absent');
    if (!parNom.has('frame-ancestors') && !entete(headers, 'x-frame-options')) {
      problèmes.push('frame-ancestors absent');
    }

    const critique = inlineNonUtilisable;

    out.push(constat({
      id: 'csp',
      famille: 'entetes',
      titre: 'Content-Security-Policy',
      statut: critique || problèmes.length > 0 ? 'warn' : 'pass',
      severite: critique ? 'elevee' : problèmes.length > 0 ? 'faible' : 'info',
      resume: critique
        ? 'Politique présente mais inopérante sur les scripts.'
        : problèmes.length > 0
          ? `${problèmes.length} point(s) à durcir : ${problèmes.join(', ')}.`
          : 'Politique présente et cohérente.',
      detail: critique
        ? "Avec `'unsafe-inline'` et sans nonce, la CSP autorise explicitement tout script inséré dans la page : elle apporte le confort d'un en-tête et la protection d'aucune. C'est la configuration la plus répandue et la plus trompeuse — elle *a* l'air protégée."
        : "L'astérisque et `data:` sont les deux échappatoires qui annulent la politique. Un nonce ou une empreinte par script est ce qui la rend réellement contraignante : le navigateur n'exécute alors que le code qu'il sait avoir écrit.",
      preuve: cspBrut,
      correction: critique
        ? "Retirer 'unsafe-inline' et ajouter un nonce par balise <script>, ou une empreinte SHA-256 pour le script statique."
        : problèmes.length > 0
          ? 'Durcir les directives signalées, en commençant par object-src et base-uri, qui protègent sans rien casser.'
          : null,
    }));
  }

  /* --- Cadrage (clickjacking) -------------------------------------------- */
  const xfo = entete(headers, 'x-frame-options');
  const frameAncestors = (() => {
    if (!cspBrut) return null;
    const d = parseCsp(cspBrut).find((x) => x.nom === 'frame-ancestors');
    return d ? d.valeurs.join(' ') : null;
  })();

  // `frame-ancestors`_prime sur X-Frame-Options et couvre les navigateurs
  // modernes : sa présence rend l'autre en-tête caduc.
  const cadreBloque = frameAncestors === "'none'" || /deny/i.test(xfo || '');

  out.push(constat({
    id: 'clickjacking',
    famille: 'entetes',
    titre: 'Cadrage externe interdit',
    statut: cadreBloque ? 'pass' : (frameAncestors || xfo) ? 'warn' : 'fail',
    severite: cadreBloque ? 'info' : (frameAncestors || xfo) ? 'moyenne' : 'elevee',
    resume: cadreBloque
      ? 'La page refuse d\'être affichée dans un cadre tiers.'
      : (frameAncestors || xfo)
        ? 'Le cadrage est autorisé depuis certaines origines.'
        : 'La page peut être affichée dans n\'importe quel cadre.',
    detail: cadreBloque
      ? 'C\'est la parade du clickjacking : une page invisible superposée à un bouton légitime, et le clic part à l\'endroit prévu par l\'attaquant.'
      : "Le risque dépend de l'usage : une page de connexion ou une action de paiement ne doivent jamais être encadrables, une page de lecture peut l'être. Le constat n'est pas l'interdiction, c'est l'absence de décision.",
    preuve: frameAncestors || xfo || null,
    correction: cadreBloque ? null : "frame-ancestors 'none' (ou 'self' si l'intégration est voulue).",
  }));

  /* --- MIME sniffing ------------------------------------------------------ */
  const nosniff = entete(headers, 'x-content-type-options');

  out.push(constat({
    id: 'nosniff',
    famille: 'entetes',
    titre: 'Interprétation du type MIME verrouillée',
    statut: /nosniff/i.test(nosniff || '') ? 'pass' : 'warn',
    severite: /nosniff/i.test(nosniff || '') ? 'info' : 'faible',
    resume: /nosniff/i.test(nosniff || '')
      ? 'Le navigateur fait confiance au type annoncé.'
      : 'Le navigateur peut deviner le type d\'une ressource.',
    detail: 'Sans cet en-tête, un fichier envoyé en `text/plain` peut être exécuté comme du JavaScript s\'il contient du HTML. C\'est ce qui transforme un téléversement anodin en exécution de code.',
    preuve: nosniff || null,
    correction: 'X-Content-Type-Options: nosniff',
  }));

  /* --- Referrer ----------------------------------------------------------- */
  const referrer = entete(headers, 'referrer-policy');
  const referrerLibre = !referrer || /unsafe-url/i.test(referrer);

  out.push(constat({
    id: 'referrer-policy',
    famille: 'entetes',
    titre: 'Politique de Referrer',
    statut: referrerLibre ? 'warn' : 'pass',
    severite: referrerLibre ? 'faible' : 'info',
    resume: referrerLibre
      ? 'L\'adresse complète, y compris sa chaîne de requête, accompagne les liens sortants.'
      : `Politique déclarée : ${referrer}.`,
    detail: "Le Referrer voyage vers le site tiers. Quand l'adresse contient un jeton — un lien de partage, une URL de confirmation — ce jeton part avec elle, et le tiers le reçoit.",
    preuve: referrer || null,
    correction: 'Referrer-Policy: strict-origin-when-cross-origin',
  }));

  /* --- Permissions -------------------------------------------------------- */
  const permissions = entete(headers, 'permissions-policy');

  out.push(constat({
    id: 'permissions-policy',
    famille: 'entetes',
    titre: 'Permissions du navigateur',
    statut: permissions ? 'pass' : 'info',
    severite: permissions ? 'info' : 'info',
    resume: permissions
      ? 'Les API sensibles sont restreintes par le site.'
      : 'Aucune restriction déclarée.',
    detail: 'Microphone, géolocalisation, caméra : ces API se demandent au cas par cas, et une page qui n\'en a aucun besoin peut les interdire par défaut. L\'absence de déclaration n\'est pas une faille — c\'est une permission laissée à la demande.',
    preuve: permissions || null,
    correction: permissions ? null : 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
  }));

  /* --- Divulgation d\'information ---------------------------------------- */
  const indices = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'x-aspnetmvc-version']
    .map((nom) => ({ nom, valeur: entete(headers, nom) }))
    .filter((e) => e.valeur);

  out.push(constat({
    id: 'divulgation',
    famille: 'entetes',
    titre: 'Identification technique masquée',
    statut: indices.length === 0 ? 'pass' : 'warn',
    severite: indices.length === 0 ? 'info' : 'faible',
    resume: indices.length === 0
      ? 'Aucun en-tête ne nomme la pile technique.'
      : indices.map((e) => `${e.nom}: ${e.valeur}`).join(' · '),
    detail: 'Nommer sa pile n\'est pas une faute : c\'est une carte offerte. Indiquer une version precise réduit le nombre d\'essais necessaires pour trouver la faille correspondante.',
    preuve: indices.length ? indices.map((e) => `${e.nom}: ${e.valeur}`).join(' | ') : null,
    correction: indices.length
      ? 'Masquer ces en-têtes à la configuration du serveur ou du reverse proxy.'
      : null,
  }));

  return out;
}

/* -------------------------------------------------------------------------- */
/* Cookies                                                                     */
/* -------------------------------------------------------------------------- */

function analyserCookies(releve) {
  const out = [];
  const cookies = listeSetCookie(releve.headers).map(parseSetCookie);
  const enHttps = new URL(releve.urlFinale).protocol === 'https:';

  if (cookies.length === 0) {
    out.push(constat({
      id: 'cookies',
      famille: 'cookies',
      titre: 'Cookies',
      statut: 'pass',
      severite: 'info',
      resume: 'Aucun cookie posé par cette réponse.',
      detail: 'Rien à corriger ici. Attention à la lecture : une page sans cookie peut être une page publique, ou une page qui pose son cookie sur une requête que cet outil n\'a pas faite.',
      preuve: null,
      correction: null,
    }));
    return out;
  }

  /* --- Secure ------------------------------------------------------------- */
  const sansSecure = enHttps ? cookies.filter((c) => !c.secure) : [];

  out.push(constat({
    id: 'cookie-secure',
    famille: 'cookies',
    titre: 'Cookies restreints au HTTPS',
    statut: sansSecure.length > 0 ? 'fail' : 'pass',
    severite: sansSecure.length > 0 ? 'elevee' : 'info',
    resume: sansSecure.length > 0
      ? `${sansSecure.length} cookie(s) sans l'attribut Secure.`
      : 'Tous les cookies sont restreints au HTTPS.',
    detail: sansSecure.length > 0
      ? "Sans `Secure`, le cookie accompagne aussi la requête en clair. Il suffit d'une ressource en `http://` — une image, un script tiers oublié — pour que la session parte en clair sur le réseau."
      : "L'attribut `Secure` empêche le cookie d'être renvoyé sur une connexion non chiffrée, y compris s'il existe encore un chemin en HTTP vers le site.",
    preuve: sansSecure.length ? sansSecure.map((c) => c.nom).join(', ') : null,
    correction: sansSecure.length ? 'Ajouter ; Secure à chacun de ces cookies.' : null,
  }));

  /* --- HttpOnly ----------------------------------------------------------- */
  const sessionsExposees = cookies.filter((c) => estCookieSession(c.nom) && !c.httpOnly);

  out.push(constat({
    id: 'cookie-httponly',
    famille: 'cookies',
    titre: 'Cookies de session inaccessibles au script',
    statut: sessionsExposees.length > 0 ? 'fail' : 'pass',
    severite: sessionsExposees.length > 0 ? 'critique' : 'info',
    resume: sessionsExposees.length > 0
      ? `${sessionsExposees.length} cookie(s) de session lisible(s) en JavaScript.`
      : 'Les cookies de session sont hors de portée du script.',
    detail: sessionsExposees.length > 0
      ? 'C\'est le constat le plus lourd de ce rapport. `HttpOnly` absent, une seule injection de script suffit à lire la session — et à la renvoyer ailleurs. Le cookie de session devient alors une clé que le voleur garde pour lui.'
      : "L'attribut `HttpOnly` retire le cookie du alcance de `document.cookie`. Il faut alors pouvoir le lire d'une autre manière pour qu'il serve à quelque chose, et c'est exactement l'intention.",
    preuve: sessionsExposees.length ? sessionsExposees.map((c) => c.nom).join(', ') : null,
    correction: sessionsExposees.length ? 'Ajouter ; HttpOnly aux cookies de session.' : null,
  }));

  /* --- SameSite ----------------------------------------------------------- */
  const sameSiteProblemes = cookies.filter((c) => {
    if (c.sameSite) return /none/i.test(c.sameSite);
    // Absent, c'est la même chose que None depuis 2020 : les navigateurs
    // modernes n'envoient plus le cookie en requêtes intersites.
    return estCookieSession(c.nom);
  });

  out.push(constat({
    id: 'cookie-samesite',
    famille: 'cookies',
    titre: 'Cookies limités aux requêtes same-site',
    statut: sameSiteProblemes.length > 0 ? 'warn' : 'pass',
    severite: sameSiteProblemes.length > 0 ? 'moyenne' : 'info',
    resume: sameSiteProblemes.length > 0
      ? `${sameSiteProblemes.length} cookie(s) sans SameSite effectif.`
      : 'SameSite est renseigné.',
    detail: 'SameSite=Lax bloque l\'envoi du cookie lors d\'une requête venue d\'un autre site — c\'est ce qui neutralise la majorité des attaques CSRF, y compris sur un site qui ne s\'en préserve pas. `None` est l\'inverse exact : le cookie part partout.',
    preuve: sameSiteProblemes.length ? sameSiteProblemes.map((c) => `${c.nom} (${c.sameSite || 'absent'})`).join(', ') : null,
    correction: 'SameSite=Lax, ou Strict quand le cookie n\'a rien à faire dans une navigation entrante.',
  }));

  /* --- Préfixes de cookie ----------------------------------------------------- */
  const cookiesSession = cookies.filter((c) => estCookieSession(c.nom));
  const prefixables = cookiesSession.filter((c) => !c.prefixe);

  /*
    Trois états, et non deux.

    Le cas intermédiaire est celui-ci : la réponse ne pose **aucun** cookie
    identifiable comme une session. Dire « les cookies de session portent un
    préfixe » serait alors une affirmation que rien ne soutient — on ne sait pas
    de quelles sessions il s'agit, puisque l'outil ne voit que la réponse
    analysée. Un constat qui affirme ce qu'il n'a pas vérifié décrédite tous
    les autres du rapport.
  */
  const aucunCookieSession = cookiesSession.length === 0;

  out.push(constat({
    id: 'cookie-prefixe',
    famille: 'cookies',
    titre: 'Préfixes de cookie appliqués',
    statut: aucunCookieSession ? 'info' : prefixables.length === 0 ? 'pass' : 'warn',
    severite: aucunCookieSession || prefixables.length === 0 ? 'info' : 'faible',
    resume: aucunCookieSession
      ? 'Aucun cookie de session identifiable dans cette réponse.'
      : prefixables.length > 0
        ? `${prefixables.length} cookie(s) de session sans préfixe.`
        : 'Les cookies de session portent un préfixe de contrainte.',
    detail: aucunCookieSession
      ? "Les cookies posés ici ne portent pas de nom de session reconnaissable : ce sont des préférences ou des identifiants de mesure. Le constat reste donc sans objet — les sessions peuvent très bien être posées sur une requête que cet outil n'a pas faite."
      : "Les préfixes `__Host-` et `__Secure-` ne sont pas une recommandation : le navigateur **refuse** de stocker un cookie ainsi préfixé s'il ne respecte pas ses conditions — pas de `Domain`, `Path=/`, `Secure`. La contrainte est appliquée par le navigateur, pas par l'application.",
    preuve: prefixables.length ? prefixables.map((c) => c.nom).join(', ') : null,
    correction: prefixables.length
      ? 'Préfixer les cookies de session par __Host- lorsque le domaine est unique.'
      : null,
  }));

  /* --- Domaine explicite -------------------------------------------------- */
  const avecDomaine = cookies.filter((c) => c.domain);

  out.push(constat({
    id: 'cookie-domaine',
    famille: 'cookies',
    titre: 'Portée des cookies limitée à l\'hôte',
    statut: avecDomaine.length > 0 ? 'warn' : 'pass',
    severite: avecDomaine.length > 0 ? 'faible' : 'info',
    resume: avecDomaine.length > 0
      ? `${avecDomaine.length} cookie(s) élargis à un domaine parent.`
      : 'Aucun cookie n\'élargit sa portée.',
    detail: "Un attribut `Domain` étend le cookie à tous les sous-domaines. Il faut l'écrire pour partager une session entre sous-domaines — et il ne faut pas l'écrire ailleurs : un sous-domaine compromis reçoit alors un cookie qui ne le concerne pas.",
    preuve: avecDomaine.length ? avecDomaine.map((c) => `${c.nom} → .${c.domain}`).join(', ') : null,
    correction: 'Retirer l\'attribut Domain des cookies qui n\'ont pas besoin d\'être partagés.',
  }));

  return out;
}

/** Un hôte couvre-t-il un cookie émis avec un `Domain` parent ? */

/* -------------------------------------------------------------------------- */
/* CORS                                                                        */
/* -------------------------------------------------------------------------- */

/** L'origine de la sonde : TLD réservé par la RFC 2606, donc jamais résoluble. */
const ORIGINE_SONDE = 'https://vigie-probe.invalid';

function analyserCors(releve) {
  const out = [];
  const probe = releve.cors;
  const headers = releve.headers || {};

  if (!probe || !probe.realise) {
    out.push(constat({
      id: 'cors',
      famille: 'cors',
      titre: 'Politique CORS',
      statut: 'info',
      severite: 'info',
      resume: 'La sonde avec origine synthétique n\'a pas pu aboutir.',
      detail: 'Sans seconde requête portant un `Origin`, impossible de distinguer un serveur correctement configuré d\'un serveur qui renvoie les données de tout le monde : la plupart répondent `*` tant qu\'on ne demande rien. Ce constat est une absence de mesure, pas une absence de risque.',
      preuve: probe && probe.raison ? probe.raison : null,
      correction: null,
    }));
    return out;
  }

  const acao = probe.acao || null;
  const credentials = String(probe.acac || '').toLowerCase() === 'true';
  const reflechi = acao === ORIGINE_SONDE;

  /* --- La réflexion d'origine ------------------------------------------- */
  //
  // C'est le constat le plus grave possible en CORS, et le seul qui soit
  // réellement exploitable : le serveur a echoed l'origine qu'on lui a donnée
  // **et** autorisé l'envoi d'identifiants. Tout site tiers peut alors lire la
  // réponse comme si c'était le sien, session comprise.
  if (reflechi && credentials) {
    out.push(constat({
      id: 'cors-reflection',
      famille: 'cors',
      titre: 'Origine renvoyée au lieu d\'être vérifiée',
      statut: 'fail',
      severite: 'critique',
      resume: 'Le serveur renvoie l\'origine reçue et autorise les identifiants.',
      detail: "C'est la faille CORS la plus grave et la plus facile à rater : le serveur ne vérifie pas *quelle* origine demande la donnée, il renvoie *celle qui demande*. Avec `Access-Control-Allow-Credentials: true`, n'importe quel site peut lire la réponse avec la session du visiteur — et agir en son nom. Aucune authentification faible n'est nécessaire : il n'y en a pas.",
      preuve: `Access-Control-Allow-Origin: ${acao} · Access-Control-Allow-Credentials: ${probe.acac}`,
      correction: 'Remplacer la réflexion par une liste d\'origines autorisées, comparées à la liste blanche.',
    }));
  } else if (reflechi) {
    out.push(constat({
      id: 'cors-reflection',
      famille: 'cors',
      titre: 'Origine renvoyée au lieu d\'être vérifiée',
      statut: 'warn',
      severite: 'moyenne',
      resume: 'Le serveur renvoie l\'origine reçue, sans autoriser les identifiants.',
      detail: "La réponse est lisible par n'importe quel site — mais sans les identifiants, un attaquant n'obtient que ce qu'un visiteur non connecté verrait. C'est une fuite de données, pas une prise de contrôle : la distinction vaut de ne pas traiter les deux de la même façon.",
      preuve: `Access-Control-Allow-Origin: ${acao}`,
      correction: 'Ne renvoyer que les origines autorisées, et toujours sans réflexion.',
    }));
  } else {
    out.push(constat({
      id: 'cors-reflection',
      famille: 'cors',
      titre: 'Origine renvoyée au lieu d\'être vérifiée',
      statut: 'pass',
      severite: 'info',
      resume: 'L\'origine de la sonde n\'a pas été renvoyée.',
      detail: 'Le serveur a refusé une origine étrangère : c\'est le comportement attendu. C\'est le seul constat CORS qui se prouve par une requête, et c\'est ce qui le distingue des vérifications de simple présence d\'en-tête.',
      preuve: probe.acao || '(aucun Access-Control-Allow-Origin renvoyé)',
      correction: null,
    }));
  }

  /* --- Contradiction de la spécification --------------------------------- */
  if (acao === '*' && credentials) {
    out.push(constat({
      id: 'cors-spec',
      famille: 'cors',
      titre: 'Joker et identifiants combinés',
      statut: 'fail',
      severite: 'elevee',
      resume: '`*` et `Access-Control-Allow-Credentials: true` sont renvoyés ensemble.',
      detail: "La spécification interdit la combinaison et le navigateur rejette la paire. Le site n'est donc pas exposé — mais l'intention est floue, et la configuration ne tient que par le navigateur : un client non conforme, un composant serveur, un ancien client mobile l'appliquent littéralement. Une configuration qui ne tient que par la bonne volonté du client n'est pas une configuration.",
      preuve: `Access-Control-Allow-Origin: * · Access-Control-Allow-Credentials: ${probe.acac}`,
      correction: 'Conserver une liste d\'origines explicite dès que les identifiants sont autorisés.',
    }));
  }

  /* --- Origines en dur ---------------------------------------------------- */
  const tiersAutorise = acao && acao !== '*' && !reflechi;

  if (tiersAutorise) {
    out.push(constat({
      id: 'cors-origines',
      famille: 'cors',
      titre: 'Origines autorisées en dur',
      statut: 'info',
      severite: 'info',
      resume: `Le serveur autorise explicitement ${acao}.`,
      detail: 'Une liste d\'origines explicite est la bonne façon de faire. Elle mérite d\'être relue de temps en temps : une origine autorisée un jour pour un développement local, et oubliée depuis, reste une porte ouverte.',
      preuve: acao,
      correction: null,
    }));
  }

  /* --- Réponse d'erreur --------------------------------------------------- */
  if (probe.acam) {
    out.push(constat({
      id: 'cors-preflight',
      famille: 'cors',
      titre: 'Vérification préalable',
      statut: 'info',
      severite: 'info',
      resume: `Méthodes autorisées : ${probe.acam}.`,
      detail: 'Le serveur répond à la requête de vérification préalable du navigateur. Cette réponse est l\'endroit où se décide si une méthode et un en-tête sont acceptés — un `*` y est plus dangereux qu\'ailleurs, puisqu\'il autorise toute méthode y compris `PUT` et `DELETE`.',
      preuve: `Access-Control-Allow-Methods: ${probe.acam}`,
      correction: null,
    }));
  }

  // Sans aucune politique annoncée, l'indiquer évite qu'un lecteur conclue
  // « pas de CORS » d'un rapport qui n'a rien trouvé.
  if (!acao) {
    out.push(constat({
      id: 'cors-aucune',
      famille: 'cors',
      titre: 'Aucune politique CORS annoncée',
      statut: 'pass',
      severite: 'info',
      resume: 'Le serveur n\'autorise aucune origine étrangère.',
      detail: 'C\'est la position par défaut du navigateur, et elle est saine tant que l\'application n\'a pas besoin d\'appeler une API depuis une autre origine. Le jour où elle en a besoin, la politique devra être écrite — et l\'outil la vérifiera.',
      preuve: null,
      correction: null,
    }));
  }

  return out;
}

/* -------------------------------------------------------------------------- */
/* Chaîne de redirections                                                       */
/* -------------------------------------------------------------------------- */

/** Hôte d'une URL, port exclu. */
function hoteDe(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function analyserChaine(releve) {
  const out = [];
  const sauts = releve.sauts || [];
  const redirections = sauts.filter((s) => s.status >= 300 && s.status < 400);

  /* --- Détection de repli en clair ---------------------------------------- */
  //
  // Un seul saut en `http` suffit à rendre le premier échange lisible. Le HSTS
  // n'y change rien : sa protection commence au moment où le navigateur reçoit
  // l'en-tête, c'est-à-dire après ce saut.
  const sautsEnClair = redirections.filter((s) => hoteDe(s.url).length > 0
    && s.url.startsWith('http://'));

  out.push(constat({
    id: 'chaine-downgrade',
    famille: 'chaine',
    titre: 'Aucun échange en clair sur le chemin',
    statut: sautsEnClair.length > 0 ? 'fail' : 'pass',
    severite: sautsEnClair.length > 0 ? 'elevee' : 'info',
    resume: sautsEnClair.length > 0
      ? `${sautsEnClair.length} saut(s) de la chaîne en HTTP.`
      : 'Toute la chaîne est en HTTPS.',
    detail: sautsEnClair.length > 0
      ? "Le visiteur est d'abord allé en clair avant d'atterrir sur la page chiffrée. La requête a déjà voyagé : la protection de HSTS ne s'applique qu'aux requêtes suivantes, jamais à celle-ci. Un intercepteur sur le réseau voit l'adresse complète et, sur un site qui n'en impose pas, les en-têtes aussi."
      : 'Aucun saut intermédiaire ne se fait en clair.',
    preuve: sautsEnClair.length ? sautsEnClair.map((s) => s.url).join(' · ') : null,
    correction: sautsEnClair.length ? 'Rediriger en 301 vers l\'équivalent HTTPS, avant tout contenu.' : null,
  }));

  /* --- Cookies posés sur une redirection --------------------------------- */
  //
  // Le cookie est envoyé à l'-intermédiaire, pas à la destination. Il
  // n'atterrit pas « au mauvais endroit » : il atterrit *avant* que le
  // visiteur n'arrive, sur un hôte qui n'est pas la destination.
  const cookiesSurRedirection = redirections.flatMap((saut) => {
    const brut = Array.isArray(saut.setCookie) ? saut.setCookie : [];
    return brut.map((c) => ({ saut, cookie: parseSetCookie(c) }));
  });

  out.push(constat({
    id: 'chaine-cookie-redirection',
    famille: 'chaine',
    titre: 'Aucun cookie posé par une redirection',
    statut: cookiesSurRedirection.length > 0 ? 'warn' : 'pass',
    severite: cookiesSurRedirection.length > 0 ? 'moyenne' : 'info',
    resume: cookiesSurRedirection.length > 0
      ? `${cookiesSurRedirection.length} cookie(s) posé(s) sur un saut de redirection.`
      : 'Les redirections ne posent aucun cookie.',
    detail: cookiesSurRedirection.length > 0
      ? "Un `Set-Cookie` émis sur une 3xx est stocké par le navigateur pour l'hôte qui redirige, **avant** que le visiteur n'atteigne la destination. Le rapport final ne le montre pas — il ne regarde que la dernière réponse. Si ce cookie est un identifiant de session, le jeton n'est pas encore émis, et il se retrouve attaché à la requête qui suit."
      : "Aucune redirection de la chaîne ne pose de cookie. Les identifiants sont posés une seule fois, par la réponse finale.",
    preuve: cookiesSurRedirection.length
      ? cookiesSurRedirection.map((c) => `${c.cookie.nom} sur ${c.saut.status} vers ${hoteDe(c.saut.location || '')}`).join(' · ')
      : null,
    correction: 'Poser les cookies depuis la réponse finale uniquement, jamais depuis une redirection.',
  }));

  /* --- Élargissement de domaine à travers un saut d'hôte ------------------ */
  const traversees = [];
  for (let i = 1; i < sauts.length; i += 1) {
    const precedent = hoteDe(sauts[i - 1].url);
    const courant = hoteDe(sauts[i].url);
    if (precedent && courant && precedent !== courant) {
      traversees.push({ de: precedent, vers: courant });
    }
  }

  // Un cookie posé avec un domaine parent couvre le suivant : il le suit.
  const fuitePossible = [];
  for (const saut of sauts) {
    const brut = Array.isArray(saut.setCookie) ? saut.setCookie : [];
    const hote = hoteDe(saut.url);
    for (const c of brut) {
      const cookie = parseSetCookie(c);
      if (!cookie.domain) continue;
      const touche = traversees.find((t) => t.de === hote && hoteDe(`https://${cookie.domain}`) === t.de);
      if (touche) fuitePossible.push({ cookie, saut: saut.url, vers: touche.vers });
    }
  }

  out.push(constat({
    id: 'chaine-domaine',
    famille: 'chaine',
    titre: 'La chaîne ne dépose pas de cookie chez un tiers',
    statut: fuitePossible.length > 0 ? 'fail' : 'pass',
    severite: fuitePossible.length > 0 ? 'elevee' : 'info',
    resume: fuitePossible.length > 0
      ? `${fuitePossible.length} cookie(s) suivent le visiteur d\'un hôte à l\'autre.`
      : 'Aucun cookie ne change de portée entre deux hôtes.',
    detail: fuitePossible.length > 0
      ? 'Un cookie posé avec un attribut `Domain` parent est renvoyé vers tous les sous-domaines. Lorsque la chaîne passe ensuite chez un autre nom, le cookie l\'accompagne. Le second hôte reçoit donc un jeton émis pour le premier — il suffit que le second soit l\'un des deux pour qu\'il puisse s\'en servir.'
      : (traversees.length > 0
        ? `La chaîne change d'hôte ${traversees.length} fois (${traversees.map((t) => `${t.de} → ${t.vers}`).join(', ')}), sans qu'aucun cookie ne soit élargi à un domaine parent.`
        : 'La chaîne reste sur un seul hôte.'),
    preuve: fuitePossible.length
      ? fuitePossible.map((f) => `${f.cookie.nom} (.${f.cookie.domain}) posé par ${hoteDe(f.saut)}`).join(' · ')
      : (traversees.length ? traversees.map((t) => `${t.de} → ${t.vers}`).join(' · ') : null),
    correction: fuitePossible.length
      ? 'Poser les cookies sans attribut Domain, et vérifier la chaîne de redirection.'
      : null,
  }));

  return out;
}

/* -------------------------------------------------------------------------- */
/* Contenu                                                                      */
/* -------------------------------------------------------------------------- */

function analyserContenu(releve) {
  const out = [];
  const enHttps = new URL(releve.urlFinale).protocol === 'https:';

  if (!enHttps || !releve.html) return out;

  /*
    Contenu mixte : une ressource `http://` dans une page `https://`.

    Le relevé est volontairement étroit — `src` et `href` seulement, et
    seulement sur une URL http. Passer au Regex sur le corps entier ramènerait
    des faux positifs dès la première mention en commentaire ou en texte, et
    un outil qui cries au loup s'éteint.
  */
  const ressourcesEnClair = new Set();
  const motif = /(?:src|href)\s*=\s*["']\s*(http:\/\/[^"'\s>]+)/gi;
  let correspondance;
  while ((correspondance = motif.exec(releve.html)) !== null) {
    const adresse = correspondance[1];
    if (/^http:\/\/(localhost|127\.|0\.0\.0\.0)/i.test(adresse)) continue;
    ressourcesEnClair.add(adresse.split('#')[0]);
  }

  out.push(constat({
    id: 'contenu-mixte',
    famille: 'entetes',
    titre: 'Aucune ressource chargée en clair',
    statut: ressourcesEnClair.size > 0 ? 'warn' : 'pass',
    severite: ressourcesEnClair.size > 0 ? 'moyenne' : 'info',
    resume: ressourcesEnClair.size > 0
      ? `${ressourcesEnClair.size} ressource(s) référencée(s) en HTTP.`
      : 'Toutes les ressources référencées sont en HTTPS.',
    detail: ressourcesEnClair.size > 0
      ? "Le navigateur refuse ces ressources sur une page chiffrée — sauf en mode mixte, que l'utilisateur peut activer d'un clic. Elles plantent aussi un avertissement à côté de l'adresse, ce qui apprend au visiteur à ignorer les avertissements."
      : "Le HTML ne référence aucune ressource en `http://`. Attention : l'audit est statique, il ne voit pas une ressource chargée par un script.",
    preuve: ressourcesEnClair.size ? [...ressourcesEnClair].slice(0, 4).join(' · ') : null,
    correction: ressourcesEnClair.size ? 'Passer les références en HTTPS, ou enraciner les ressources chez soi.' : null,
  }));

  return out;
}

/* -------------------------------------------------------------------------- */
/* Point d'entrée                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Analyse un relevé. Fonction pure : aucun réseau, aucune horloge en dehors
 * du champ `releve.maintenant`.
 *
 * @param {object} releve  Faits collectés par le handler.
 * @returns {{checks: object[], familles: object[], synthese: object}}
 */
function analyser(releve) {
  const checks = [
    ...analyserTransport(releve),
    ...analyserEntetes(releve),
    ...analyserCookies(releve),
    ...analyserCors(releve),
    ...analyserChaine(releve),
    ...analyserContenu(releve),
  ];

  const tries = [...checks].sort(parGravite);

  const synthese = {
    total: checks.length,
    echecs: checks.filter((c) => c.statut === 'fail').length,
    avertissements: checks.filter((c) => c.statut === 'warn').length,
    conformes: checks.filter((c) => c.statut === 'pass').length,
    critiques: checks.filter((c) => c.severite === 'critique' && c.statut !== 'pass').length,
  };

  // Les familles ne sont renvoyées que si la sonde a réellement produit des
  // faits : afficher « CORS » en amertume quand la sonde n'a pas abouti
  // ferait croire à un constat.
  const familles = FAMILLES
    .map((f) => ({ ...f, nombre: checks.filter((c) => c.famille === f.id).length }))
    .filter((f) => f.nombre > 0);

  return { checks: tries, familles, synthese };
}

module.exports = {
  analyser,
  parseSetCookie,
  parseCsp,
  entete,
  listeSetCookie,
  estCookieSession,
  analyserChaine,
  analyserCors,
  analyserCookies,
  analyserEntetes,
  analyserTransport,
  analyserContenu,
  parGravite,
  hoteDe,
  FAMILLES,
  SEVERITES,
  ORIGINE_SONDE,
};
