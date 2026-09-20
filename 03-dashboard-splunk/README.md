# Dashboard Splunk — Détection brute force / password spraying

## Contenu
Tableau de bord Splunk avec 4 panneaux pour la supervision des tentatives de connexion échouées.

| Panneau | Type de visualisation | Objectif |
|---|---|---|
| Échecs de connexion dans le temps | Graphique en courbes | Évolution/pic d'activité anormale |
| Top 10 comptes ciblés | Tableau de statistiques | Identifier les cibles principales |
| Échecs vs Réussites | Graphique à secteurs | Vue proportionnelle rapide |
| Comptes avec activité suspecte (>5 échecs) | Tableau de statistiques | Liste d'alerte actionnable |

## Requêtes SPL utilisées

**Panneau 1 — Échecs dans le temps**
```spl
index=main EventCode=4625
| timechart span=1h count
```

**Panneau 2 — Top comptes ciblés**
```spl
index=main EventCode=4625
| stats count by Nom_du_compte
| sort -count
| head 10
```

**Panneau 3 — Échecs vs Réussites**
```spl
index=main (EventCode=4625 OR EventCode=4624)
| eval statut=if(EventCode=4625, "Échec", "Réussite")
| stats count by statut
```

**Panneau 4 — Comptes suspects**
```spl
index=main EventCode=4625
| stats count by Nom_du_compte
| where count > 5
```
