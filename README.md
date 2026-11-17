# Scanner de factures

Application web (PWA) pour photographier ou importer des factures et tickets, les recadrer automatiquement, puis les envoyer dans un dossier OneDrive choisi.

- Prise de photo (appareil photo du téléphone), import de photos et PDF un par un ou par lots, glisser-déposer sur PC.
- Détection automatique des bords, redressement de la perspective, rotation, noir et blanc, conversion en PDF.
- Choix du dossier OneDrive (et création de dossier), envoi direct via Microsoft Graph.
- Installable sur l'écran d'accueil (manifest + service worker).

Site statique, sans serveur : aucune donnée ne passe par l'hébergeur ; le téléphone parle directement à Microsoft.

## Réglages

`config.js` :
- `clientId` : ID d'application (client) de l'inscription Azure (Entra ID).
- `defaultPath` : dossier proposé à la première connexion.

## Inscription Azure (une fois)

1. entra.microsoft.com → Applications → Inscriptions d'applications → Nouvelle inscription.
2. Comptes : « Comptes dans un annuaire d'organisation et comptes Microsoft personnels ».
3. URI de redirection : plateforme **Application monopage (SPA)**, `https://scanner-factures.onrender.com/` (ajouter aussi `http://localhost:8765/` pour tester en local).
4. Autorisations demandées par l'appli à la connexion : `User.Read`, `Files.ReadWrite`, `offline_access`.

## Render

Static Site relié à ce dépôt, Build Command vide, Publish Directory `.` (ou Blueprint via `render.yaml`). Chaque push sur `main` redéploie.

## Test local

```
python3 -m http.server 8765
```
puis http://localhost:8765/

## Lancement manuel du traitement (dossier `api/`)

Le bouton « Lancer le traitement maintenant » appelle un petit service (`api/server.js`, sans dépendance) qui vérifie le compte Microsoft de l'utilisateur puis déclenche la tâche planifiée Claude « Traitement des factures » par son API.

Render, Web Service gratuit relié à ce dépôt :
- Root Directory : `api` ; Build Command : vide (ou `npm install`) ; Start Command : `node server.js`
- Variables d'environnement :
  - `ROUTINE_ID` : identifiant de la tâche planifiée (`trig_…`)
  - `ROUTINE_TOKEN` : jeton API de la tâche (claude.ai/code/routines → la tâche → Modifier → + API → Generate token) — **secret, uniquement dans Render**
  - `ALLOWED_EMAILS` : comptes autorisés à lancer, séparés par des virgules
  - `ALLOWED_ORIGINS` : `https://scanner-factures.onrender.com`
  - `QONTO_LOGIN` et `QONTO_SECRET_KEY` : clé API Qonto (Qonto web → Paramètres → Intégrations et partenaires → Clé API) pour le bouton « Importer » des factures électroniques — **secret, uniquement dans Render**

## Suivi

La section « Suivi des envois » relit chaque document envoyé depuis cet appareil : renommé (nom `AAAAMMJJ_FOURNISSEUR_MONTANT€TTC`), classé (dans `Fournisseurs/…` ou `À vérifier`) et rapproché (colonne « Transaction Qonto » de `Dépenses 2026.xlsx`).
