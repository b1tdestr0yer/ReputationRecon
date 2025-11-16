import { useNavigate, useLocation } from 'react-router-dom'
import { useTheme } from '../contexts/ThemeContext'

const TopBar = () => {
  const { theme, toggleTheme } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()

  const isCachePage = location.pathname === '/cache'

  return (
    <div className="top-bar">
      <div className="top-bar-content">
        <div className="top-bar-title" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>
          <i className="fas fa-shield-alt"></i>
          <span>ReputationRecon</span>
        </div>
        <div className="top-bar-actions">
          {!isCachePage && (
            <button className="cache-browser-btn" onClick={() => navigate('/cache')} title="Browse cache">
              <i className="fas fa-database"></i>
              <span>Browse Cache</span>
            </button>
          )}
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
    </div>
  )
}

export default TopBar

