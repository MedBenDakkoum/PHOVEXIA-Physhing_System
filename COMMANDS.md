# Commandes récurrentes

Fichier local, ignoré par Git. Une commande par bloc, une phrase par commande.

## Démo — ÉTAT ACTUEL : CASSÉ

> **Ne pas lancer `demo_setup` aujourd'hui.** `scans/management/commands/load_demo_samples.py` importe encore `_BASE_KEYS`, nom supprimé de `scans/services/inference_client.py` (remplacé par `_BASE_KEY_TO_FRIENDLY`). La commande échoue à l'import avant de créer quoi que ce soit.

Preuve de l'erreur, sans lancer la démo :

```
cd backend
.\phishing_env\Scripts\python.exe -c "import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings'); django.setup(); import scans.management.commands.load_demo_samples"
```

Message réel obtenu : `ImportError: cannot import name '_BASE_KEYS' from 'scans.services.inference_client'`.

La même erreur casse la collecte de `scans/test_demo_samples.py` (le test importe aussi `_BASE_KEYS`).

### Ce qu'il faudra faire une fois le bug corrigé (ne pas exécuter maintenant)

La commande devra tourner dans le worker, pas dans `web` (le volume média est en lecture seule sur `web`).

```
cd backend
docker compose -f docker-compose.yml -f ..\collector\docker-compose.collector.yml --profile full exec -T worker python manage.py demo_setup
```

Elle ne doit s'exécuter que si `ALLOW_DEMO_SETUP` vaut vrai dans `backend/.env`.

Elle crée trois comptes avec le mot de passe `DEMO_PASSWORD` : `demo.admin@example.org` (admin), `demo.analyst@example.org` (analyste), `demo.user@example.org` (utilisateur).

Elle active aussi le modèle d'inférence, les marques protégées et 20 scans d'exemple, sans contacter les URL d'origine.

### Tester un échantillon de phishing (après correction seulement)

```
cd backend
docker compose -f docker-compose.yml -f ..\collector\docker-compose.collector.yml --profile full exec -T worker python manage.py demo_setup
```

Puis ouvrir `http://127.0.0.1:8080/app` avec `demo.user@example.org` et le mot de passe `DEMO_PASSWORD`.

L'historique doit afficher les 20 échantillons avec le libellé « Échantillon du jeu de test (Phish360) ».

### Flux blocklist (après correction seulement)

Un analyste ajoute un domaine depuis `/app/blocklist` avec une raison.

Le scan suivant de ce domaine doit répondre immédiatement `phishing`, score `1.0` et `detection_source=blocklist`, sans passer par le collecteur.

Le retrait d'une entrée exige une raison (BR-12) et écrit une entrée d'audit.

### Règle marque pour google.com (après correction seulement)

La page d'accueil officielle `https://google.com/` devient `legitimate` avec `detection_source=brand_policy` et le drapeau `OFFICIAL_BRAND_HOMEPAGE`, même si le modèle seul dit `phishing`.

Un lien profond sur le domaine officiel (par exemple `https://google.com/...`) n'est jamais rendu légitime automatiquement : si le modèle dit `phishing` ou `uncertain`, le scan part en revue.

## Vérifications de base

```
cd backend
.\phishing_env\Scripts\python.exe -m ruff check .
```

```
cd backend
$env:DB_ENGINE='sqlite'; .\phishing_env\Scripts\python.exe -m pytest -q --ignore=scans/test_demo_samples.py
```

```
cd frontend
npm run build
```

```
cd backend
docker compose -f docker-compose.yml -f ..\collector\docker-compose.collector.yml --profile full config --services
```

Ne jamais utiliser `docker compose down -v` : cela détruit les volumes de la base et des médias.
