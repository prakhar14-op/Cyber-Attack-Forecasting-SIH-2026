import React, { useState, useEffect } from 'react'
import { AnimatePresence, motion } from 'motion/react'

interface FlipWordsProps {
  words: string[]
  interval?: number
  className?: string
}

const FlipWords: React.FC<FlipWordsProps> = ({ words, interval = 2400, className = '' }) => {
  const [idx, setIdx] = useState(0)

  useEffect(() => {
    const t = setInterval(() => setIdx(i => (i + 1) % words.length), interval)
    return () => clearInterval(t)
  }, [words.length, interval])

  return (
    <AnimatePresence mode="wait">
      <motion.span
        key={idx}
        initial={{ y: 32, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: -32, opacity: 0 }}
        transition={{ duration: 0.42, ease: [0.22, 1, 0.36, 1] }}
        className={className}
        style={{ display: 'inline-block', textDecoration: 'underline', textDecorationColor: '#10B981', textDecorationThickness: '3px', textUnderlineOffset: '8px' }}
      >
        {words[idx]}
      </motion.span>
    </AnimatePresence>
  )
}

export default FlipWords
