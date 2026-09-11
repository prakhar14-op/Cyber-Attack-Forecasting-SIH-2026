import { Children, cloneElement, createRef, forwardRef, isValidElement, useEffect, useMemo, useRef } from 'react'
import type { HTMLAttributes, ReactElement, ReactNode, RefAttributes } from 'react'
import gsap from 'gsap'
import './CardSwap.css'

export const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>((props, ref) => (
  <div ref={ref} {...props} className={`card ${props.className ?? ''}`.trim()} />
))
Card.displayName = 'Card'

interface CardSwapProps {
  width?: number; height?: number; cardDistance?: number; verticalDistance?: number
  delay?: number; pauseOnHover?: boolean; skewAmount?: number; children: ReactNode
}

export default function CardSwap({ width = 460, height = 340, cardDistance = 55, verticalDistance = 65, delay = 4500, pauseOnHover = true, skewAmount = 5, children }: CardSwapProps) {
  const childArr = useMemo(() => Children.toArray(children), [children])
  const refs = useMemo(() => childArr.map(() => createRef<HTMLDivElement>()), [childArr])
  const order = useRef(Array.from({ length: childArr.length }, (_, index) => index))
  const timeline = useRef<gsap.core.Timeline | null>(null)
  const interval = useRef<number>()
  const container = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const total = refs.length
    const slot = (index: number) => ({ x: index * cardDistance, y: -index * verticalDistance, z: -index * cardDistance * 1.5, zIndex: total - index })
    refs.forEach((ref, index) => { if (ref.current) gsap.set(ref.current, { ...slot(index), xPercent: -50, yPercent: -50, skewY: skewAmount, transformOrigin: 'center', force3D: true }) })
    const swap = () => {
      const [front, ...rest] = order.current
      if (front === undefined) return
      const element = refs[front]?.current
      if (!element) return
      const tl = gsap.timeline(); timeline.current = tl
      tl.to(element, { y: '+=500', duration: 2, ease: 'elastic.out(0.6,0.9)' }).addLabel('promote', '-=1.8')
      rest.forEach((item, index) => {
        const node = refs[item]?.current; if (!node) return
        tl.set(node, { zIndex: slot(index).zIndex }, 'promote').to(node, { ...slot(index), duration: 2, ease: 'elastic.out(0.6,0.9)' }, `promote+=${index * 0.15}`)
      })
      const back = slot(total - 1)
      tl.addLabel('return', 'promote+=0.1').call(() => gsap.set(element, { zIndex: back.zIndex }), undefined, 'return').to(element, { ...back, duration: 2, ease: 'elastic.out(0.6,0.9)' }, 'return').call(() => { order.current = [...rest, front] })
    }
    swap(); interval.current = window.setInterval(swap, delay)
    const node = container.current
    const pause = () => { timeline.current?.pause(); window.clearInterval(interval.current) }
    const resume = () => { timeline.current?.play(); interval.current = window.setInterval(swap, delay) }
    if (pauseOnHover && node) { node.addEventListener('mouseenter', pause); node.addEventListener('mouseleave', resume) }
    return () => { window.clearInterval(interval.current); if (node) { node.removeEventListener('mouseenter', pause); node.removeEventListener('mouseleave', resume) } }
  }, [cardDistance, delay, pauseOnHover, refs, skewAmount, verticalDistance])

  return <div ref={container} className="card-swap-container" style={{ width, height }}>{childArr.map((child, index) => isValidElement(child) ? cloneElement(child as ReactElement<HTMLAttributes<HTMLDivElement> & RefAttributes<HTMLDivElement>>, { key: index, ref: refs[index], style: { width, height, ...child.props.style } }) : child)}</div>
}
