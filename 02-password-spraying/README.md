# Password Spraying — Détection

## Contexte
Simulation d'une attaque password spraying sur l'AD nivard.local — un seul mot de passe testé sur plusieurs comptes distincts, technique utilisée pour contourner les politiques de verrouillage de compte.

## Détection Splunk (SPL)

```spl
index=main EventCode=4625
| bucket _time span=5m
| stats dc(Nom_du_compte) as comptes_distincts by _time
| where comptes_distincts > 5
```

## Pourquoi dc() et pas count()
Le signal du password spraying est la **diversité des comptes touchés** dans une fenêtre de temps courte, pas le volume total d'échecs — contrairement au brute force qui cible un seul compte.

## Conclusion
Vrai Positif (simulation) — pattern de password spraying confirmé sur 6 comptes de test dans une fenêtre de 5 minutes.
