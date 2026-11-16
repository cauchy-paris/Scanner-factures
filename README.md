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
