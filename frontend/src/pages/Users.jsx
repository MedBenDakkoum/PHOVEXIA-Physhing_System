import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CircleAlert, Lock, MoreHorizontal, Pencil, RotateCcw, ScrollText, Search, UserPlus, UserX, Users as UsersIcon } from "lucide-react";
import { createUser, reactivateUser, suspendUser, updateUser, listUsers } from "../api/users";
import { ROLES, ROLE_VALUES } from "../api/constants";
import { ApiError } from "../api/errors";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import Avatar from "../components/ui/Avatar";
import { RoleBadge, ROLE_META, StatusBadge } from "../components/ui/Badges";
import Button from "../components/ui/Button";
import { Segmented, SelectField, Switch, TextField } from "../components/ui/Fields";
import { Menu, MenuItem, MenuSeparator } from "../components/ui/Menu";
import { ConfirmDialog, Modal } from "../components/ui/Overlay";
import PageHeader from "../components/ui/PageHeader";
import Pagination from "../components/ui/Pagination";
import { EmptyState, ErrorState, TableSkeleton } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDebounce } from "../hooks/useDebounce";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { displayName, formatDate, formatNumber, fullName, relativeTime } from "../utils/format";

const PAGE_SIZE = 10;

function CreateUserModal({ onClose, onCreated }) {
  const toast = useToast();
  const [form, setForm] = useState({ email: "", password: "", first_name: "", last_name: "", role: "end_user" });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setErrors({});
    setFormError("");
    try {
      const created = await createUser({ ...form, is_active: true });
      toast.success("Compte créé", created.email);
      onCreated();
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setErrors(err.fieldErrors);
      setFormError(err.message);
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      closeDisabled={saving}
      title="Créer un compte"
      description="Choisissez les informations et le rôle du nouvel utilisateur."
      footer={<>
        <Button variant="ghost" onClick={onClose} disabled={saving}>Annuler</Button>
        <Button variant="gold" type="submit" form="create-user-form" loading={saving}>Créer le compte</Button>
      </>}
    >
      <form id="create-user-form" onSubmit={submit} style={{ display: "grid", gap: 18 }} noValidate>
        {formError && <div className="alert alert-error" role="alert"><CircleAlert size={18} /><span>{formError}</span></div>}
        <TextField label="Adresse e-mail" type="email" autoComplete="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} error={errors.email} required data-autofocus />
        <TextField label="Mot de passe temporaire" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} error={errors.password} required />
        <div className="form-grid">
          <TextField label="Prénom" value={form.first_name} onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))} error={errors.first_name} />
          <TextField label="Nom" value={form.last_name} onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))} error={errors.last_name} />
        </div>
        <SelectField label="Rôle" value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))} error={errors.role}>
          {ROLE_VALUES.map((role) => <option key={role} value={role}>{ROLES[role]?.label || role}</option>)}
        </SelectField>
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------- modification */
function EditUserModal({ target, isSelf, onClose, onSaved }) {
  const toast = useToast();
  const [form, setForm] = useState({
    first_name: target.first_name || "",
    last_name: target.last_name || "",
    role: target.role,
    is_active: target.is_active,
  });
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  // Seuls les champs modifiés sont envoyés (PATCH)
  const payload = {};
  if (form.first_name.trim() !== (target.first_name || "")) payload.first_name = form.first_name.trim();
  if (form.last_name.trim() !== (target.last_name || "")) payload.last_name = form.last_name.trim();
  if (form.role !== target.role) payload.role = form.role;
  if (form.is_active !== target.is_active) payload.is_active = form.is_active;
  const dirty = Object.keys(payload).length > 0;

  const submit = async (e) => {
    e.preventDefault();
    if (!dirty) return onClose();
    setSaving(true);
    setErrors({});
    setFormError("");
    try {
      const updated = await updateUser(target.id, payload);
      toast.success("Utilisateur mis à jour", displayName(updated));
      onSaved(updated);
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setErrors(err.fieldErrors);
      setFormError(err.message);
      setSaving(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      closeDisabled={saving}
      title="Modifier l'utilisateur"
      description={target.email}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Annuler
          </Button>
          <Button variant="gold" type="submit" form="edit-user-form" loading={saving} disabled={!dirty}>
            Enregistrer
          </Button>
        </>
      }
    >
      <form id="edit-user-form" onSubmit={submit} style={{ display: "grid", gap: 18 }} noValidate>
        {formError && (
          <div className="alert alert-error" role="alert">
            <CircleAlert size={18} />
            <span>{formError}</span>
          </div>
        )}
        <div className="form-grid">
          <TextField
            label="Prénom"
            value={form.first_name}
            onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))}
            error={errors.first_name}
            data-autofocus
          />
          <TextField
            label="Nom"
            value={form.last_name}
            onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))}
            error={errors.last_name}
          />
        </div>

        <div className="field">
          <span className="field-label" id="role-label">
            Rôle
          </span>
          <div className="role-grid" role="radiogroup" aria-labelledby="role-label">
            {ROLE_VALUES.map((r) => {
              const meta = ROLE_META[r] || ROLE_META.end_user;
              const Icon = meta.icon;
              return (
                <button
                  key={r}
                  type="button"
                  role="radio"
                  aria-checked={form.role === r}
                  className="role-option"
                  disabled={isSelf}
                  onClick={() => setForm((f) => ({ ...f, role: r }))}
                >
                  <span className="role-ico">
                    <Icon size={20} />
                  </span>
                  <span>
                    <strong>{ROLES[r]?.label || r}</strong>
                    <span className="desc">{meta.desc}</span>
                  </span>
                </button>
              );
            })}
          </div>
          {errors.role && <span className="field-error">{errors.role}</span>}
        </div>

        <Switch
          checked={form.is_active}
          onChange={(v) => setForm((f) => ({ ...f, is_active: v }))}
          disabled={isSelf}
          label={form.is_active ? "Compte actif" : "Compte suspendu"}
          description={form.is_active ? "L'utilisateur peut se connecter." : "L'utilisateur ne peut plus se connecter."}
        />

        {isSelf && (
          <span className="lock-note">
            <Lock size={13} /> Vous ne pouvez pas modifier votre propre rôle ni suspendre votre propre compte.
          </span>
        )}
      </form>
    </Modal>
  );
}

/* ------------------------------------------------------------------- page */
export default function Users() {
  useDocumentTitle("Utilisateurs");
  const { user: me, refreshUser } = useAuth();
  const toast = useToast();

  const [search, setSearch] = useState("");
  const q = useDebounce(search.trim(), 350);
  const [role, setRole] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState(null); // { kind: "suspend" | "reactivate", user }
  const [busy, setBusy] = useState(false);

  const { data, error, loading, reload } = useAsync(
    (signal) => listUsers({ search: q, role, is_active: active }, signal),
    [q, role, active]
  );
  useEffect(() => setPage(1), [q, role, active]);

  const users = data || [];
  const pageItems = users.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const nActive = users.filter((u) => u.is_active).length;
  const filtered = Boolean(q || role || active);

  const resetFilters = () => {
    setSearch("");
    setRole("");
    setActive("");
  };

  const runConfirm = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      if (confirm.kind === "suspend") {
        await suspendUser(confirm.user.id); // DELETE = suspension du compte
        toast.success("Compte suspendu", displayName(confirm.user));
      } else {
        await reactivateUser(confirm.user.id);
        toast.success("Compte réactivé", displayName(confirm.user));
      }
      setConfirm(null);
      reload();
    } catch (err) {
      toast.error("Action impossible", err.message);
    } finally {
      setBusy(false);
    }
  };

  const onSaved = async (updated) => {
    setEditing(null);
    if (updated.id === me.id) await refreshUser().catch(() => {});
    reload();
  };

  return (
    <>
      <PageHeader
        title="Utilisateurs"
        description="Consultez les comptes, ajustez les rôles et suspendez l'accès en cas de besoin."
        actions={
          <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", flexWrap: "wrap", gap: 12 }}>
          <Button variant="gold" icon={UserPlus} onClick={() => setCreating(true)}>Créer un compte</Button>
          <div className="stat-pills" aria-label="Résumé">
            <div className="stat-pill">
              <b>{formatNumber(users.length)}</b> {filtered ? "résultats" : "comptes"}
            </div>
            <div className="stat-pill">
              <b>{formatNumber(nActive)}</b> actifs
            </div>
            <div className="stat-pill">
              <b>{formatNumber(users.length - nActive)}</b> suspendus
            </div>
          </div>
          </div>
        }
      />

      <section className="card list-card" aria-label="Liste des utilisateurs">
        <div className="toolbar">
          <div className="grow">
            <TextField
              size="sm"
              icon={Search}
              type="search"
              placeholder="Rechercher par e-mail, prénom ou nom"
              aria-label="Rechercher un utilisateur"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="group">
            <Segmented
              label="Filtrer par rôle"
              value={role}
              onChange={setRole}
              options={[{ value: "", label: "Tous les rôles" }, ...ROLE_VALUES.map((r) => ({ value: r, label: ROLES[r]?.label || r }))]}
            />
            <Segmented
              label="Filtrer par statut"
              value={active}
              onChange={setActive}
              options={[
                { value: "", label: "Tous" },
                { value: "true", label: "Actifs" },
                { value: "false", label: "Suspendus" },
              ]}
            />
          </div>
        </div>

        {loading && !data ? (
          <TableSkeleton rows={6} cols={5} />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : users.length === 0 ? (
          <EmptyState
            icon={UsersIcon}
            title="Aucun utilisateur trouvé"
            action={
              filtered && (
                <Button variant="ghost" onClick={resetFilters}>
                  Réinitialiser les filtres
                </Button>
              )
            }
          >
            {filtered ? "Aucun compte ne correspond à votre recherche." : "Aucun compte n'existe pour le moment."}
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap" style={{ opacity: loading ? 0.6 : 1, transition: "opacity .2s" }}>
              <table className="tbl tbl-stack">
                <thead>
                  <tr>
                    <th>Utilisateur</th>
                    <th>Rôle</th>
                    <th>Statut</th>
                    <th>Inscription</th>
                    <th>Dernière connexion</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((u) => {
                    const isSelf = u.id === me.id;
                    return (
                      <tr key={u.id} className={u.is_active ? "" : "row-muted"}>
                        <td>
                          <div className="cell-user">
                            <Avatar user={u} />
                            <div style={{ minWidth: 0, textAlign: "left" }}>
                              <strong className="truncate">
                                {fullName(u) || "Sans nom"} {isSelf && <span className="badge badge-gold badge-nodot" style={{ marginLeft: 6 }}>Vous</span>}
                              </strong>
                              <span className="truncate">{u.email}</span>
                            </div>
                          </div>
                        </td>
                        <td data-label="Rôle">
                          <RoleBadge role={u.role} />
                        </td>
                        <td data-label="Statut">
                          <StatusBadge active={u.is_active} />
                        </td>
                        <td data-label="Inscription" className="muted">
                          {formatDate(u.date_joined)}
                        </td>
                        <td data-label="Dernière connexion" className="muted" title={u.last_login || ""}>
                          {u.last_login ? relativeTime(u.last_login) : "Jamais"}
                        </td>
                        <td className="col-actions">
                          <Menu
                            trigger={
                              <button className="icon-btn" aria-label={`Actions pour ${u.email}`}>
                                <MoreHorizontal size={20} />
                              </button>
                            }
                          >
                            <MenuItem icon={Pencil} onClick={() => setEditing(u)}>
                              Modifier
                            </MenuItem>
                            <Link to={`/app/admin/audit?user=${u.id}`} className="menu-item" role="menuitem">
                              <ScrollText size={17} /> Voir son activité
                            </Link>
                            <MenuSeparator />
                            {u.is_active ? (
                              <MenuItem
                                icon={UserX}
                                danger
                                disabled={isSelf}
                                title={isSelf ? "Vous ne pouvez pas suspendre votre propre compte" : undefined}
                                onClick={() => setConfirm({ kind: "suspend", user: u })}
                              >
                                Suspendre le compte
                              </MenuItem>
                            ) : (
                              <MenuItem icon={RotateCcw} onClick={() => setConfirm({ kind: "reactivate", user: u })}>
                                Réactiver le compte
                              </MenuItem>
                            )}
                          </Menu>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={page} pageSize={PAGE_SIZE} total={users.length} onPage={setPage} />
          </>
        )}
      </section>

      {editing && (
        <EditUserModal target={editing} isSelf={editing.id === me.id} onClose={() => setEditing(null)} onSaved={onSaved} />
      )}

      {creating && <CreateUserModal onClose={() => setCreating(false)} onCreated={() => { setCreating(false); reload(); }} />}

      <ConfirmDialog
        open={Boolean(confirm)}
        onClose={() => setConfirm(null)}
        onConfirm={runConfirm}
        loading={busy}
        tone={confirm?.kind === "suspend" ? "danger" : "gold"}
        title={confirm?.kind === "suspend" ? "Suspendre ce compte ?" : "Réactiver ce compte ?"}
        confirmLabel={confirm?.kind === "suspend" ? "Suspendre" : "Réactiver"}
        message={
          confirm &&
          (confirm.kind === "suspend" ? (
            <>
              <strong style={{ color: "var(--text)" }}>{displayName(confirm.user)}</strong> ne pourra plus se connecter. Le compte et
              son historique sont conservés : vous pourrez le réactiver à tout moment.
            </>
          ) : (
            <>
              <strong style={{ color: "var(--text)" }}>{displayName(confirm.user)}</strong> pourra de nouveau se connecter avec son
              rôle actuel ({ROLES[confirm.user.role]?.label || confirm.user.role}).
            </>
          ))
        }
      />
    </>
  );
}
