import { ArrowUpRight, Menu, X } from 'lucide-react'
import { motion } from 'motion/react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'

import { BrandMark } from '@/components/ui/BrandMark'

const navLinks = [
  { label: 'Overview', href: '#overview' },
  { label: 'Technology', href: '#technology' },
  { label: 'Intelligence', href: '#intelligence' },
  { label: 'Architecture', href: '#architecture' },
] as const

export function LandingNavbar() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 28)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <motion.header
      className={`lp-navbar${scrolled ? ' lp-navbar-scrolled' : ''}`}
      initial={{ opacity: 0, y: -18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="lp-navbar-inner">
        <a className="lp-brand-link" href="#overview" aria-label="Sentinel Forecast home">
          <BrandMark />
        </a>
        <nav className="lp-nav-links" aria-label="Landing sections">
          {navLinks.map((item) => <a key={item.href} href={item.href}>{item.label}</a>)}
        </nav>
        <Link className="lp-console-button" to="/analyze">
          Console <ArrowUpRight size={14} />
        </Link>
        <button
          className="lp-menu-button"
          type="button"
          aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((value) => !value)}
        >
          {menuOpen ? <X size={19} /> : <Menu size={19} />}
        </button>
      </div>
      {menuOpen && (
        <motion.nav
          className="lp-mobile-menu"
          aria-label="Mobile landing sections"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
        >
          {navLinks.map((item) => (
            <a key={item.href} href={item.href} onClick={() => setMenuOpen(false)}>{item.label}</a>
          ))}
          <Link to="/analyze" onClick={() => setMenuOpen(false)}>Launch console <ArrowUpRight size={14} /></Link>
        </motion.nav>
      )}
    </motion.header>
  )
}
