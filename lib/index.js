/**
 * Vigie — point d'entrée public.
 *
 * La bibliothèque est utilisable seule, sans serveur :
 *
 *   const { auditer } = require('vigie');
 *   const rapport = await auditer('exemple.fr');
 *
 * Le serveur HTTP n'est qu'un brancheur parmi d'autres ; c'est délibéré. Un
 * recruteur peut donc lire 200 lignes et les faire tourner en trois lignes,
 * sans déployer quoi que ce soit.
 */
const { recupererPage, requeteUne, cibleValide, estRedirection } = require('./fetch-page');
const { analyserTls } = require('./tls');
const { analyser, ORIGINE_SONDE } = require('./analyze');
const { calculerScore, verdictPour, prioriser } = require('./score');

/** Sonde CORS : une requête de plus, avec une origine étrangère. */
async function sonderCors(url) {
  try {
    const cible = cibleValide(url);
    const reponse = await requeteUne(cible, {
      timeoutMs: 5000,
      maxBytes: 64 * 1024,
      extraHeaders: { Origin: ORIGINE_SONDE },
    });

    if (estRedirection(reponse.status)) {
      return { realise: false, raison: `redirection ${reponse.status}` };
    }

    return {
      realise: true,
      statut: reponse.status,
      acao: reponse.headers['access-control-allow-origin'] || null,
      acac: reponse.headers['access-control-allow-credentials'] || null,
      acam: reponse.headers['access-control-allow-methods'] || null,
    };
  } catch (err) {
    return { realise: false, raison: err && err.code ? err.code : 'UNREACHABLE' };
  }
}

/**
 * Audite une adresse et renvoie le rapport complet.
 *
 * @param {string} url  Adresse http ou https. Le schéma est facultatif.
 * @returns {Promise<object>}
 */
async function auditer(url) {
  const page = await recupererPage(url);
  const finale = new URL(page.urlFinale);

  // Sans TLS sur la réponse finale, il n'y a pas de certificat à lire.
  const tls = finale.protocol === 'https:'
    ? await analyserTls(finale.hostname, finale.port ? Number(finale.port) : 443)
    : null;

  const cors = await sonderCors(page.urlFinale);

  const releve = {
    url: page.url,
    urlFinale: page.urlFinale,
    chaine: page.chaine,
    sauts: page.sauts,
    status: page.status,
    headers: page.headers,
    html: page.html,
    dureeMs: page.dureeMs,
    tls,
    cors,
  };

  const { checks, familles, synthese } = analyser(releve);
  const calcul = calculerScore(checks);

  return {
    url: page.url,
    urlFinale: page.urlFinale,
    redirections: page.redirects > 0 ? page.chaine : null,
    statutHttp: page.status,
    score: calcul.score,
    verdict: verdictPour(calcul).mot,
    commentaire: verdictPour(calcul).phrase,
    critique: calcul.critique,
    familles,
    checks: prioriser(checks),
    synthese,
    dureeMs: page.dureeMs,
  };
}

module.exports = {
  auditer,
  analyser,
  analyserTls,
  calculerScore,
  verdictPour,
  prioriser,
  recupererPage,
  parseSetCookie: require('./analyze').parseSetCookie,
  parseCsp: require('./analyze').parseCsp,
  ORIGINE_SONDE,
};
