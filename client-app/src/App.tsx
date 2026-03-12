import { SocketProvider, useSocket } from './context/SocketContext'
import { Login } from './components/Login'
import { Chat } from './components/Chat'

const AppContent = () => {
  const { user } = useSocket()
  return user ? <Chat /> : <Login />
}

function App() {
  return (
    <SocketProvider>
      <AppContent />
    </SocketProvider>
  )
}

export default App
