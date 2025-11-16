import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ThemeProvider } from './contexts/ThemeContext'
import TopBar from './components/TopBar'
import HomePage from './pages/HomePage'
import CacheBrowser from './components/CacheBrowser'
import HelpPage from './pages/HelpPage'

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <TopBar />
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/cache" element={<CacheBrowser />} />
          <Route path="/help" element={<HelpPage />} />
        </Routes>
      </ThemeProvider>
    </BrowserRouter>
  )
}

export default App

