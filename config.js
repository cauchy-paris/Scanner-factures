// Réglages de l'appli. L'identifiant d'application vient de l'inscription Azure (Entra ID) ; ce n'est pas un secret.
window.SCANNER_CONFIG = {
  clientId: "",                 // « ID d'application (client) » de l'inscription Azure
  tenant: "common",             // "common" = tout compte Microsoft (pro ou personnel)
  // Dossier proposé par défaut à la première connexion (ignoré s'il n'existe pas dans le OneDrive connecté)
  defaultPath: ["Comptabilité", "Exercice 2026", "Achat", "Factures", "À traiter"],
  autoFolderNote: "Ce dossier est traité automatiquement chaque matin à 7 h 38."
};
