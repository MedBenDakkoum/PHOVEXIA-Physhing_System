# Phishing Multimodal : frontend

Interface React (Vite) du backend Django « Phishing Multimodal API ».
Les noms de champs, rôles, actions d'audit et endpoints reprennent exactement ceux du backend.

## Démarrage

```bash
npm install
cp .env.example .env      # optionnel
npm run dev               # http://localhost:5173
```

Le backend Django doit tourner sur `http://127.0.0.1:8000` (`python manage.py runserver`).
En développement, Vite relaie `/api/*` vers Django : **aucune configuration CORS n'est nécessaire**.

```bash
npm run build             # production -> dist/
npm run preview
```

## Production

Servez `dist/` et l'API derrière le même domaine (nginx : `/` -> dist, `/api/` -> Django).
Si le front est sur un autre domaine, renseignez `VITE_API_URL` et ajoutez `django-cors-headers` côté backend.

## Navigation

| URL | Page | Accès |
|---|---|---|
| `/` | Accueil (première page affichée) | public |
| `/about`, `/location`, `/contact` | À propos, Localisation, Contact | public |
| `/login`, `/register` | Connexion, inscription | public (redirige vers `/app` si connecté) |
| `/app` | Tableau de bord | connecté |
| `/app/profile` | Mon profil | connecté |
| `/app/admin/users`, `/app/admin/audit` | Utilisateurs, journal d'audit | administrateur |

- Le bouton « Se connecter » de l'accueil mène à `/login` ; une fois connecté il devient « Mon espace ».
- Chaque page publique a un bouton **Retour** (historique, sinon accueil) ; les pages de connexion ont « Retour à l'accueil ».
- La déconnexion ramène à l'accueil.

## Personnaliser les coordonnées

Adresse, téléphone, e-mail, horaires et position GPS de la carte sont dans **`src/config/site.js`**
(valeurs d'exemple à remplacer). La page Contact prépare le message dans la messagerie de l'utilisateur
(`mailto:`) car le backend n'expose pas d'endpoint de contact.

## Correspondance avec le backend

| Écran | Endpoints utilisés |
|---|---|
| Connexion / Inscription | `POST /api/auth/login/`, `POST /api/auth/register/` |
| Session | `POST /api/auth/refresh/` (rotation gérée), `POST /api/auth/logout/` |
| Profil | `GET/PATCH /api/auth/me/`, `POST /api/auth/change-password/` |
| Utilisateurs (admin) | `GET /api/auth/users/` (`role`, `is_active`, `search`), `PATCH` / `DELETE /api/auth/users/{id}/` |
| Journal d'audit (admin) | `GET /api/audit/logs/` (`user`, `user_email`, `action`, `date_from`, `date_to`, `page`, `page_size`) |
| Tableau de bord | Agrège les endpoints ci-dessus (admin) ; vue simplifiée pour `analyst` et `viewer` |

Comportements alignés sur l'API :
- `DELETE /users/{id}/` suspend le compte (jamais de suppression) ; la réactivation passe par `PATCH is_active`.
- Les rôles `admin` / `analyst` / `viewer` et les 10 actions d'audit ont les mêmes libellés que le backend.
- Access token (15 min) renouvelé automatiquement ; les rafraîchissements simultanés sont fusionnés car le refresh token est à usage unique.
- Throttling (429), erreurs de validation par champ et messages Django sont traduits en français.
- Un administrateur ne peut pas modifier son propre rôle ni se suspendre (garde-fou d'interface).

## Structure

```
src/
  api/         client JWT, constantes, un module par domaine (auth, users, audit)
  context/     Auth, Thème (Nuit / Aube), Toasts
  components/  brand (emblème, logo), ui (champs, modales, menus…), charts
  layout/      PublicLayout, AppShell, AuthLayout, gardes de routes
  config/      site.js (coordonnées du site public)
  pages/       Login, Register, Dashboard, Profile, Users, AuditLogs
  pages/public Home, About, Location, Contact
  styles/      tokens, composants, layout, pages
```

Les modules Décisions, Blocklist et Modèle (actions déjà prévues dans l'audit) n'ont pas encore d'endpoints :
ils apparaissent comme « Prochainement » sur le tableau de bord.

> Les jetons JWT sont stockés dans `localStorage`. Pour un durcissement supplémentaire, envisagez des cookies HttpOnly côté backend.
