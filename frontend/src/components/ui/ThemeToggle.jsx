import { Moon, Sun } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";

export default function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const dark = theme === "dark";
  return (
    <button
      className="icon-btn"
      onClick={toggle}
      aria-label={dark ? "Passer au thème clair (Aube)" : "Passer au thème sombre (Nuit)"}
      title={dark ? "Thème Aube" : "Thème Nuit"}
    >
      {dark ? <Sun size={20} /> : <Moon size={20} />}
    </button>
  );
}
