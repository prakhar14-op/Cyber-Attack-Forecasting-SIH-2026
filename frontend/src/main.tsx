import React from 'react'
import ReactDOM from 'react-dom/client'
import { RouterProvider } from 'react-router'

import { router } from '@/app/router'
import '@/styles/index.css'

const root = document.getElementById('root')

if (!root) {
  throw new Error('Application root element was not found')
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
