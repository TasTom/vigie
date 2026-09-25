/**
 * Score de configuration et verdict de l'audit de sécurité.
 *
 * ## Pourquoi une pondération
 *
 * Compter les constats pour un point chacun dirait qu'un `Referrer-Policy`
 * absent pèse autant qu'un cookie de session lisible en JavaScript. Ce n'est
 * pas le cas, et l'écart est enorme : le second est une prise de contrôle de
 * session, le premier une fuite d'URL sur un lien partagé.
 *
 * Les poids sont donc explicites et lisibles ici. C'est le seul endroit du
 * module où il y a une opinion ; tout le reste est mesuré.
 *
 * ## Ce que le score ne dit pas
 *
 * Il ne dit pas si un site est sûr. Il mesure la conformité à une liste de
 * pratiques de configuration connues. Un site peut afficher un excellent score
 * et rester vulnérable à une injection SQL : ce genre de faille ne se lit pas
 * dans un en-tête. Inversement, un site sans CSP n'est pas pour autant
 * attaquable aujourd'hui.
 *
 * La page qui présente le rapport le dit en toutes lettres. Un score qui se
 * lirait comme une garantie serait un mensonge, et un mensonge dans un outil
 * de sécurité est le pire des défauts.
 */

const INFO = 'info';
const WARN = 'warn';
const PASS = 'pass';
const FAIL = 'fail';

/**
 * Poids par vérification. Absente de cette table = poids 1.
 *
 * Lecture : 5 pour ce qui mène à une prise de contrôle ou à une fuite directe,
 * 4 pour une defense absente sur un mécanisme de sécurité, 2 pour ce qui
 * facilite l'exploitation, 1 pour l'hygiène, 0 pour une mesure.
 */
const POIDS = {
  // Prise de contrôle ou fuite directe
  'cors-reflection': 5,
  'cookie-httponly': 5,
  'tls-hote': 5,
  'tls-expiration': 5,
  https: 5,
  'chaine-domaine': 4,
  'cookie-secure': 4,

  // Défense absente sur un mécanisme de sécurité
  'tls-chaine': 4,
  'tls-version': 4,
  hsts: 4,
  csp: 4,
  clickjacking: 4,
  'chaine-downgrade': 4,

  // Facilite l'exploitation
  'cookie-samesite': 3,
  'chaine-cookie-redirection': 3,
  'cors-spec': 3,
  'contenu-mixte': 2,
  nosniff: 2,
  divulgation: 2,
  'referrer-policy': 2,

  // Hygiène, sans effet direct
  'cookie-prefixe': 1,
  'cookie-domaine': 1,
  'permissions-policy': 1,
  cookies: 1,
  'tls-present': 1,

  // Information pure
  'cors-origines': 0,
  'cors-preflight': 0,
  'cors-aucune': 0,
  'tls-redirect': 0,
};

/** Points obtenus par un constat, sur son poids. */
function pointsPour(statut, poids) {
  if (poids === 0) return 0;
  if (statut === PASS) return poids;
  if (statut === FAIL) return 0;
  if (statut === WARN) return poids / 2;
  return 0;
}

/** Calcule le score sur 100 et les compteurs. */
function calculerScore(checks) {
  let poidsTotal = 0;
  let poidsObtenus = 0;

  const compteurs = { fail: 0, warn: 0, pass: 0, info: 0 };

  for (const check of checks) {
    const poids = POIDS[check.id] !== undefined ? POIDS[check.id] : 1;
    poidsTotal += poids;
    poidsObtenus += pointsPour(check.statut, poids);
    if (compteurs[check.statut] !== undefined) compteurs[check.statut] += 1;
  }

  // Un site sans aucun en-tête de sécurité ne doit pas obtenir 50 par défaut :
  // l'absence de tout est un constat, pas une absence de constat. On retire
  // donc les absences de la base, et on ne les recompte pas non plus.
  const score = poidsTotal === 0
    ? 100
    : Math.round((poidsObtenus / poidsTotal) * 100);

  return {
    score,
    poidsTotal,
    poidsObtenus,
    compteurs,
    // Un constat critique ne s'efface jamais derrière un score élevé :
    // c'est la raison d'être de ce champ.
    critique: checks.some((c) => c.statut === FAIL && c.severite === 'critique'),
  };
}

/**
 * Verdict en une phrase, gradué sur le score mais corrigé par le critique.
 *
 * Un site qui affiche 82 avec un cookie de session lisible en JavaScript ne
 * doit pas être présenté comme « bon ». Le mot du verdict porte donc la
 * réserve, même quand le score est élevé.
 */
function verdictPour(calcul) {
  if (calcul.critique) {
    return {
      mot: 'Critique',
      phrase: 'Au moins un constat permettrait une prise de contrôle. Le score ne le reflète pas : à corriger en premier.',
    };
  }

  if (calcul.score >= 90) {
    return {
      mot: 'Solide',
      phrase: 'Configuration de sécurité cohérente. Les points restants sont des recommandations d\'hygiène, pas des failles.',
    };
  }

  if (calcul.score >= 75) {
    return {
      mot: 'Correct',
      phrase: 'Les mécanismes de sécurité sont en place. Quelques points méritent d\'être repris.',
    };
  }

  if (calcul.score >= 50) {
    return {
      mot: 'Incomplet',
      phrase: 'Plusieurs défenses manquent. Un site n\'a pas besoin de tout, mais ce qui est là devrait l\'être correctement.',
    };
  }

  return {
    mot: 'À reprendre',
    phrase: 'La configuration de sécurité est faible sur des points essentiels. C\'est le moment de la durcir.',
  };
}

/** Les constats à traiter en premier : échecs, puis gravité. */
const RANG_SEVERITE = { critique: 0, elevee: 1, moyenne: 2, faible: 3, info: 4 };
const RANG_STATUT = { fail: 0, warn: 1, pass: 2 };

function prioriser(checks) {
  return [...checks].sort((a, b) => {
    const st = RANG_STATUT[a.statut] - RANG_STATUT[b.statut];
    if (st !== 0) return st;
    return RANG_SEVERITE[a.severite] - RANG_SEVERITE[b.severite];
  });
}

module.exports = { calculerScore, verdictPour, prioriser, POIDS, INFO, WARN, PASS, FAIL };
