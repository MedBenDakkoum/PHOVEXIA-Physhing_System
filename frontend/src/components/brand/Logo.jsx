import { Link } from "react-router-dom";
import Crest from "./Crest";

export default function Logo({ to = "/", size = 42, sub = "Détection du phishing", onClick }) {
  const content = (
    <>
      <Crest size={size} />
      <div>
        <div className="brand-name">
          PHISHING
          <br />
          MULTIMODAL
        </div>
        {sub && <div className="brand-sub">{sub}</div>}
      </div>
    </>
  );
  return to ? (
    <Link to={to} className="brand" onClick={onClick} aria-label="Phishing Multimodal, accueil">
      {content}
    </Link>
  ) : (
    <div className="brand">{content}</div>
  );
}
