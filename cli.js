/**
 * Vigie en ligne de commande.
 *
 *   node cli.js exemple.fr
 *   node cli.js exemple.fr --json
 *
 * L'outil tourne sans configuration, sans clé et sans déploiement : c'est ce
 * qui permet de le tester en une commande pendant un entretien.
 */
const { auditer } = require('./lib');

const ORDRE_STATUT = { fail: 0, warn: 1, pass: 2, info: 3 };

/** Couleurs ANSI, désactivées quand la sortie est redirigée ou sans TTY. */
const couleurs = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const ESC = String.fromCharCode(27) + '[';
const peinture = (code, texte) => (couleurs ? `${ESC}${code}m${texte}${ESC}0m` : texte);

const gras = (t) => peinture('1', t);
const rouge = (t) => peinture('31', t);
const jaune = (t) => peinture('33', t);
const vert = (t) => peinture('32', t);
const gris = (t) => peinture('90', t);

const STATUTS = {
  fail: { symbole: '✕', couleur: rouge },
  warn: { symbole: '!', couleur: jaune },
  pass: { symbole: '✓', couleur: vert },
  info: { symbole: 'i', couleur: gris },
};

function afficher(rapport) {
  console.log('');
  console.log(gras(rapport.urlFinale));

  const teinte = rapport.critique ? rouge : rapport.score >= 75 ? vert : jaune;
  console.log('');
  console.log(`  ${teinte(gras(String(rapport.score)))} / 100 — ${gras(rapport.verdict)}`);
  console.log(`  ${rapport.commentaire}`);
  console.log('');

  if (rapport.critique) {
    console.log(  rouge(gras('  ⚠ Constat critique : à traiter avant tout le reste.')));
    console.log('');
  }

  let familleCourante = null;
  // Le moteur rend ses constats triés par gravité, pas groupés par famille.
  // Sans regroupement ici, la sortie alterne « En-têtes », « Transport »,
  // « En-têtes » : le lecteur perd le fil de ce qu'il est en train de lire.
  const parFamille = rapport.familles
    .map(({ id }) => {
      const items = rapport.checks.filter((c) => c.famille === id);
      items.sort((a, b) => ORDRE_STATUT[a.statut] - ORDRE_STATUT[b.statut]);
      return { id, items };
    })
    .filter(({ items }) => items.length > 0);

  for (const famille of parFamille) {
    const nom = rapport.familles.find((f) => f.id === famille.id);
    console.log(`  ${gras((nom ? nom.nom : famille.id).toUpperCase())}`);

    for (const check of famille.items) {
      const statut = STATUTS[check.statut] || STATUTS.info;
      const ligne = `    ${statut.couleur(statut.symbole)} ${check.titre}`;

      // Sur un constat conforme, la ligne de résumé suffit : le rapport doit
      // pouvoir être lu en diagonale, et non lu mot à mot.
      console.log(check.statut === 'pass' ? gris(ligne) : ligne);
      if (check.statut !== 'pass') {
        console.log(`      ${check.resume}`);
        if (check.correction) console.log(`      ${gris('→ ' + check.correction)}`);
      }
    }
  }

  console.log('');
  console.log(gris(`  ${rapport.synthese.echecs} écart(s) · ${rapport.synthese.avertissements} à durcir · ${rapport.synthese.conformes} conforme(s)`));
  console.log('');
}

async function main() {
  const args = process.argv.slice(2);
  const enJson = args.includes('--json');
  const cible = args.find((a) => !a.startsWith('--'));

  if (!cible) {
    console.error("Usage : node cli.js <adresse> [--json]");
    console.error("Exemple : node cli.js exemple.fr");
    process.exit(1);
  }

  try {
    const rapport = await auditer(cible);

    if (enJson) {
      console.log(JSON.stringify(rapport, null, 2));
    } else {
      afficher(rapport);
    }

    // Un constat critique fait sortir en 1 : l'outil est utilisable dans une
    // chaîne CI, et « aucun écart » ne se confond pas avec « à revoir ».
    process.exit(rapport.critique ? 1 : 0);
  } catch (err) {
    console.error(`  Échec : ${err.message}`);
    if (err.code) console.error(gris(`  (${err.code})`));
    process.exit(2);
  }
}

main();

module.exports = { ORDRE_STATUT };
