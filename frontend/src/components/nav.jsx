export default function Navbar({ modules, selected, onSelect }) {
  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <div className="brand">BlackICE</div>
        
        <select
          className="module-select"
          value={selected || ""}
          onChange={(e) => onSelect(e.target.value)}
        >
          <option value="" disabled>
            Select Module
          </option>
          {modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </div>
    </nav>
  );
}
