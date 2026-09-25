/**
 * Limitation de débit « au mieux », partagée par les routes qui exposent une
 * ressource coûteuse : envoi d'e-mail, appel à un modèle facturé, audit d'un
 * site distant.
 *
 * **Ce que ce module est** : un frein contre l'usage répété depuis une même
 * adresse. Il suffit à protéger un quota et à éviter qu'une boucle côté
 * visiteur ne déclenche des dizaines d'appels.
 *
 * **Ce qu'il n'est pas** : une protection contre un attaquant déterminé. En
 * serverless, la mémoire ne survit pas d'une instance à l'autre, et plusieurs
 * instances servent en parallèle : un compteur en mémoire se contourne en
 * répartissant les requêtes. Une vraie limite passe par un stockage partagé
 * (Redis, Upstash) ou par le pare-feu de l'hébergeur. Ce module freine, il ne
 * garantit rien — et le dire ici évite de croire le problème réglé.
 *
 * Le compteur est volontairement par clé (l'adresse IP) et non global : une
 * limite globale permettrait à un seul visiteur de bloquer le site pour tous.
 */

/** Au-delà de ce nombre d'entrées suivies, les compteurs expirés sont purgés. */
const MAX_ENTREES = 500;

/**
 * Crée un limiteur.
 *
 * @param {object} options
 * @param {number} options.max       Requêtes autorisées par fenêtre.
 * @param {number} options.windowMs  Durée de la fenêtre, en millisecondes.
 */
function createRateLimiter({ max, windowMs }) {
  /** Clé → horodatages des requêtes retenues dans la fenêtre courante. */
  const hits = new Map();

  return {
    /**
     * Enregistre une requête et dit si elle dépasse le quota.
     *
     * Seules les requêtes **acceptées** sont comptées. Une requête rejetée ne
     * prolonge donc pas le blocage : au bout de la fenêtre, le visiteur repart
     * avec un quota neuf, qu'il ait réessayé entre-temps ou non. Compter les
     * rejets punirait une boucle de retry côté navigateur — et, sur une adresse
     * partagée (box d'entreprise, réseau mobile), maintiendrait tout le monde
     * bloqué à cause d'un seul utilisateur.
     */
    isLimited(key) {
      const now = Date.now();
      const recent = (hits.get(key) || []).filter((time) => now - time < windowMs);

      // Quota atteint : on rend la main sans ajouter d'horodatage.
      if (recent.length >= max) {
        hits.set(key, recent);
        return true;
      }

      recent.push(now);
      hits.set(key, recent);

      if (hits.size > MAX_ENTREES) {
        for (const [entryKey, times] of hits) {
          if (!times.some((time) => now - time < windowMs)) hits.delete(entryKey);
        }
      }

      return false;
    },

    /** Remet les compteurs à zéro. Réservé aux tests. */
    reset() {
      hits.clear();
    },
  };
}

module.exports = { createRateLimiter, MAX_ENTREES };
