import { useState, useRef, useEffect } from 'react'
import { AssessmentResponse } from '../types'
import { sendChatMessage } from '../services/api'
import { useTheme } from '../contexts/ThemeContext'

interface ChatbotProps {
  assessmentData: AssessmentResponse
  isOpen: boolean
  onClose: () => void
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

const Chatbot = ({ assessmentData, isOpen, onClose }: ChatbotProps) => {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const { theme } = useTheme()

  const isDarkMode = theme === 'dark'

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
    }
  }, [isOpen])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const handleSend = async () => {
    if (!input.trim() || isLoading) return

    const userMessage: Message = {
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput('')
    setIsLoading(true)

    try {
      const response = await sendChatMessage(assessmentData, userMessage.content)
      const assistantMessage: Message = {
        role: 'assistant',
        content: response.message,
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, assistantMessage])
    } catch (error) {
      const errorMessage: Message = {
        role: 'assistant',
        content: `Error: ${error instanceof Error ? error.message : 'Failed to get response from AI'}`,
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  if (!isOpen) return null

  return (
    <div className="chatbot-side-tab">
      <div className="chatbot-container">
        <div className="chatbot-header">
          <div className="chatbot-header-content">
            <i className="fas fa-robot"></i>
            <h3>AI Assistant</h3>
            <span className="chatbot-subtitle">Ask questions about this assessment</span>
          </div>
          <button className="chatbot-close-btn" onClick={onClose} title="Close">
            <i className="fas fa-times"></i>
          </button>
        </div>

        <div className="chatbot-messages">
          {messages.length === 0 && (
            <div className="chatbot-welcome">
              <i className="fas fa-comments"></i>
              <p>Ask me anything about the security assessment for <strong>{assessmentData.entity_name}</strong>.</p>
              <p className="chatbot-suggestions">Try asking:</p>
              <ul>
                <li>"What are the main security concerns?"</li>
                <li>"Explain the CVE findings"</li>
                <li>"What does the trust score mean?"</li>
                <li>"Are there any critical vulnerabilities?"</li>
              </ul>
            </div>
          )}

          {messages.map((message, index) => (
            <div
              key={index}
              className={`chatbot-message ${message.role === 'user' ? 'user-message' : 'assistant-message'}`}
            >
              <div className="message-avatar">
                {message.role === 'user' ? (
                  <i className="fas fa-user"></i>
                ) : (
                  <i className="fas fa-robot"></i>
                )}
              </div>
              <div className="message-content">
                <div className="message-text">{message.content}</div>
                <div className="message-time">
                  {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="chatbot-message assistant-message">
              <div className="message-avatar">
                <i className="fas fa-robot"></i>
              </div>
              <div className="message-content">
                <div className="message-text">
                  <div className="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        <div className="chatbot-input-container">
          <input
            ref={inputRef}
            type="text"
            className="chatbot-input"
            placeholder="Type your question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            disabled={isLoading}
          />
          <button
            className="chatbot-send-btn"
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            title="Send message"
          >
            <i className="fas fa-paper-plane"></i>
          </button>
        </div>
      </div>
    </div>
  )
}

export default Chatbot

