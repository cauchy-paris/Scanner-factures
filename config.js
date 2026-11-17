// Réglages de l'appli. L'identifiant d'application vient de l'inscription Azure (Entra ID) ; ce n'est pas un secret.
window.SCANNER_CONFIG = {
  clientId: "3900ac65-953a-4169-89cf-5c2e012d7bf7",               // « ID d'application (client) » de l'inscription Azure
  tenant: "cauchy-paris.fr",    // inscription Azure mono-organisation ; "common" si multi-organisations
  // Dossier proposé par défaut à la première connexion (ignoré s'il n'existe pas dans le OneDrive connecté)
  defaultPath: ["Comptabilité", "Exercice 2026", "Achat", "Factures", "À traiter"],
  // Service de lancement du traitement (Web Service Render du dossier api/)
  apiUrl: "https://scanner-factures-api.onrender.com",
  // Tableau des dépenses, pour afficher l'état « rapproché »
  expensesPath: "Comptabilité/Exercice 2026/Achat/Factures/Dépenses 2026.xlsx",
  // Factures électroniques Qonto : dossier « Fournisseurs » (ciblé par son id, il peut être déplacé)
  // et registre des factures déjà rangées (dossier _Automatisation)
  suppliersFolderId: "017P3ARQVKKZ3MJY6QCNGJGYE2TQP37RYG",
  automationFolderId: "017P3ARQQAC45FNQBOS5GIWQLCH2Q5TZFV",
  autoFolderNote: "Ce dossier est traité automatiquement chaque matin à 7 h 38."
};
