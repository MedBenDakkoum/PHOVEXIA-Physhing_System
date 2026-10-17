import { initials } from "../../utils/format";

export default function Avatar({ user, size, className = "" }) {
  return (
    <span className={`avatar ${size ? `avatar-${size}` : ""} ${className}`} aria-hidden="true">
      {initials(user)}
    </span>
  );
}
