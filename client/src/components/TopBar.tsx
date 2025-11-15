import { useTheme } from '../contexts/ThemeContext'

const TopBar = () => {
  const { theme, toggleTheme } = useTheme()

  return (
    <div className="top-bar">
      <div className="top-bar-content">
        <div className="top-bar-title">
          <i className="fas fa-shield-alt"></i>
          <span>ReputationRecon</span>
        </div>
        <button className="theme-toggle-btn" onClick={toggleTheme} title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}>
          {theme === 'light' ? (
            <>
              <i className="fas fa-moon"></i>
              <span>Dark Mode</span>
            </>
          ) : (
            <>
              <i className="fas fa-sun"></i>
              <span>Light Mode</span>
            </>
          )}
        </button>
      </div>
    </div>
  )
}

export default TopBar

