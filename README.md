# Vigie

**Audit de la configuration de sécurité d'un site web.** TLS, en-têtes de
sécurité, cookies, politique CORS, chaîne de redirections.

```bash
# Sans installation
npx github:TasTom/vigie exemple.fr

# Ou en clonant
git clone https://github.com/TasTom/vigie
cd vigie && npm install && node cli.js exemple.fr
```

```
https://example.com/

  74 / 100 — Incomplet
  Plusieurs défenses manquent. Un site n'a pas besoin de tout, mais ce qui est
  là devrait l'être correctement.

  TRANSPORT ET CERTIFICAT
    ✓ Le site est servi en HTTPS
    ✓ Version de TLS proposée
    ✓ Le certificat est valide

  EN-TÊTES DE SÉCURITÉ
    ✕ HSTS
      Aucun durcissement du transport par cet en-tête.
      → Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Aucune dépendance de production, aucune clé, aucun déploiement : une commande
et le rapport s'affiche.

---

## Ce que cet outil ne fait pas

Il vérifie une **liste nommée et finie de réglages**. Il ne cherche ni injection
SQL, ni XSS, ni faille d'authentification : ces familles-là exigent d'envoyer des
charges utiles et de comprendre l'application, pas de lire ses en-têtes.

C'est dit dans le rapport lui-même, pas seulement ici. Un score de configuration
lu comme un verdict de sécurité apprendrait à son lecteur de faire confiance
aux rapports — y compris à ceux d'un vrai test d'intrusion, qui sont exacts.

## Ce qui le distingue d'un scanner d'en-têtes

La plupart ne lisent que **la réponse finale**. Trois constats ici n'existent
qu'en analysant **toute la chaîne**, et disparaissent entièrement d'un rapport
qui s'arrête au dernier saut :

| Constat | Pourquoi un scanner standard ne le voit pas |
|---|---|
| Un cookie posé sur une **redirection** | Le `Set-Cookie` est stocké par le navigateur pour l'hôte intermédiaire, **avant** que le visiteur n'atteigne la destination. Il n'apparaît pas dans la réponse finale. |
| Un saut en **`http`** avant le `https` | Le premier échange a déjà voyagé en clair. HSTS ne s'applique qu'aux requêtes *suivantes* — il ne rattrape pas celle-ci. |
| Un cookie à **`Domain` parent** | Il accompagne le visiteur d'un hôte à l'autre : le second hôte reçoit un jeton émis pour le premier. |

Le test CORS, lui, **ne se prouve pas** par la présence d'un en-tête. Un serveur
qui n'a rien à cacher répond `*` tant qu'on ne demande rien — la réflexion d'une
origine étrangère est undetectable par simple lecture. Vigie envoie donc une
seconde requête portant `Origin: https://vigie-probe.invalid` (TLD réservé par
la RFC 2606, donc résoluble par personne) et compare les deux réponses.

## Score pondéré, et un critique qui ne se compense pas

Un `Referrer-Policy` absent ne pèse pas comme un cookie de session lisible en
JavaScript. Les poids sont explicites dans `lib/score.js` : c'est le seul endroit
du projet où il y a une opinion, tout le reste est mesuré.

Un constat critique **jamais** ne se rattrape derrière une bonne note. Un site
peut afficher 82 avec une session lisible en JavaScript ; le verdict porte
alors la réserve, et le rapport le dit.

## Utilisation en bibliothèque

```js
const { auditer } = require('vigie');

const rapport = await auditer('exemple.fr');

rapport.score;             // 74
rapport.critique;          // false
rapport.checks;            // constats triés par gravité
rapport.familles;          // regroupement par catégorie
```

## Sécurité de l'outil lui-même

C'est un proxy qui sort sur le web à l'adresse d'un visiteur : c'est aussi un
point d'entrée **SSRF** potentiel. `169.254.169.254` distribue les identifiants
d'instance de nombreux hébergeurs cloud, et une boucle locale donne accès à tout
ce que le serveur voit.

La défense est en un seul point : l'adresse IP est contrôlée **au moment de la
connexion**, via la résolution DNS pontée de `lib/fetch-page.js`, pas avant. Un
contrôle par résolution séparée laisserait une fenêtre pendant laquelle le DNS
peut répondre une adresse publique au contrôle, puis une adresse privée à la
connexion. Chaque saut de redirection est revalidé.

```
$ vigie http://127.0.0.1:5000/
  Échec : Cette adresse n'est pas accessible depuis l'extérieur.
  (BLOCKED_ADDRESS)
```

La sonde TLS **réutilise cette même résolution** plutôt que d'en écrire une
sienne. Sinon l'analyse du certificat deviendrait un second point d'entrée
indépendant : un nom refusé par le proxy accepté par la sonde, ou l'inverse.

## Deux pièges rencontrés, documentés parce qu'ils sont invisibles

**Le shebang manquant.** `package.json` déclare `cli.js` comme binaire via `bin`,
et npm se contente de le *lier*. Sans shebang, l'installation par `npx` réussit,
le fichier est bien présent, et l'exécution ne produit rien — aucune erreur, aucune
sortie. Le défaut n'apparaît qu'après installation, jamais dans le dépôt où l'on
lance toujours `node cli.js`.

**`getSession().getCipher()` renvoie `undefined` sur Node 17+.**

```js
// ✗ Ne fonctionne pas
const chiffrement = socket.getSession().getCipher();  // undefined

// ✓
const chiffrement = socket.getCipher();
```

La première forme affichait « pas de chiffrement » sur une connexion
parfaitement chiffrée. C'est le pire défaut qu'un outil de sécurité puisse avoir :
il signale une absence qui n'existe pas, et son lecteur apprend à ignorer ses
rapports. Un test la verrouille.

## Tests

```bash
npm test     # 55 tests
```

Aucun réseau, aucun serveur de test : le module analysé est une **fonction
pure**, qui reçoit un relevé et n'appelle ni socket ni horloge. C'est ce qui
permet de couvrir un certificat expiré, un cookie de session sans `HttpOnly` ou
une réflexion d'origine avec identifiants — des situations qu'aucun site public
ne consent à présenter.

## Licence

MIT — voir [LICENSE](LICENSE).
