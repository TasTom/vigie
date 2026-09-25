import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Les tests ne font aucun réseau : le module testé ne fait ni l'un ni
    // l'autre, et c'est ce qui permet de couvrir un certificat expiré ou une
    // réflexion CORS sans monter un serveur TLS.
    environment: 'node',
    include: ['test/**/*.test.js'],
  },
});
