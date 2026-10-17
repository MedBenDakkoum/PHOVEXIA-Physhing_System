import BackLink from "./BackLink";

/** Bandeau héroïque (ciel nocturne) en tête des pages publiques secondaires. */
export default function PageHero({ title, lead, children }) {
  return (
    <section className="sky page-hero">
      <div className="page-hero-in">
        <BackLink tone="sky" />
        <h1 className="page-hero-title">{title}</h1>
        {lead && <p className="hero-lead">{lead}</p>}
        {children}
      </div>
    </section>
  );
}
