import { useCallback, useEffect, useRef, useState } from 'react'
import * as THREE from 'three'

const NODE_POSITIONS = [
  [-3.2, 1.8, -0.8], [-2.5, 0.1, 0.4], [-2.8, -1.7, -0.2], [-1.2, 2.4, -1.1],
  [-0.9, 0.9, 0.5], [-1.3, -0.9, -0.1], [-0.4, -2.2, -1.0], [0.8, 1.9, -0.2],
  [0.4, 0.2, 0.9], [0.9, -1.5, 0.2], [2.1, 2.5, -1.2], [2.5, 0.8, 0.4],
  [2.0, -0.7, -0.4], [2.8, -2.0, -1.0], [3.7, 1.5, -0.5], [3.8, -0.3, 0.3],
] as const

const EDGES = [
  [0, 1], [0, 3], [1, 2], [1, 4], [2, 5], [3, 4], [3, 7], [4, 5], [4, 7],
  [4, 8], [5, 6], [5, 8], [5, 9], [7, 8], [7, 10], [7, 11], [8, 9], [8, 11],
  [8, 12], [9, 12], [9, 13], [10, 11], [10, 14], [11, 12], [11, 14], [11, 15],
  [12, 13], [12, 15], [14, 15],
] as const

const PACKET_EDGES = [3, 8, 12, 16, 20, 24] as const

/**
 * Tooltip copy for each node. The hero is an illustrative topology — no capture
 * is loaded on the landing page — so the metadata deliberately describes the
 * *shape* of the graph (zone, role, link count) instead of inventing telemetry.
 */
interface NodeMeta {
  label: string
  zone: string
  role: string
  status: string
}

const NODE_META: readonly NodeMeta[] = [
  { label: 'host-01', zone: 'Internal', role: 'Workstation', status: 'Ambient traffic' },
  { label: 'host-02', zone: 'Internal', role: 'File share', status: 'Ambient traffic' },
  { label: 'host-03', zone: 'Internal', role: 'Workstation', status: 'Ambient traffic' },
  { label: 'host-04', zone: 'Edge', role: 'VPN concentrator', status: 'Ambient traffic' },
  { label: 'host-05', zone: 'Internal', role: 'Directory service', status: 'Ambient traffic' },
  { label: 'host-06', zone: 'Internal', role: 'Workstation', status: 'Ambient traffic' },
  { label: 'host-07', zone: 'Internal', role: 'Print server', status: 'Ambient traffic' },
  { label: 'host-08', zone: 'Edge', role: 'Gateway', status: 'Sample threat path' },
  { label: 'host-09', zone: 'Internal', role: 'Application server', status: 'Ambient traffic' },
  { label: 'host-10', zone: 'Internal', role: 'Workstation', status: 'Ambient traffic' },
  { label: 'host-11', zone: 'External', role: 'Peer endpoint', status: 'Ambient traffic' },
  { label: 'host-12', zone: 'Internal', role: 'Database', status: 'Ambient traffic' },
  { label: 'host-13', zone: 'Internal', role: 'Build agent', status: 'Ambient traffic' },
  { label: 'host-14', zone: 'Internal', role: 'Workstation', status: 'Ambient traffic' },
  { label: 'host-15', zone: 'External', role: 'Peer endpoint', status: 'Ambient traffic' },
  { label: 'host-16', zone: 'External', role: 'Peer endpoint', status: 'Ambient traffic' },
]

const LINK_COUNTS = NODE_POSITIONS.map(
  (_, index) => EDGES.filter(([from, to]) => from === index || to === index).length,
)

const THREAT_INDEX = 7
const AUTO_SPIN_SPEED = 0.11 // radians per second

function vectorAt(index: number) {
  const position = NODE_POSITIONS[index]
  if (!position) return new THREE.Vector3()
  return new THREE.Vector3(position[0], position[1], position[2])
}

function nodeScale(index: number) {
  if (index === THREAT_INDEX) return 1.55
  return index % 5 === 0 ? 1.2 : 0.86
}

function nodeColor(index: number) {
  if (index === THREAT_INDEX) return 0xfb7185
  return index % 4 === 0 ? 0xa78bfa : 0x7dd3fc
}

/**
 * Radial-gradient sprite used as an additive halo. This fakes the look of an
 * UnrealBloomPass without a post-processing pipeline, which matters here because
 * the canvas is transparent and composited over the page background.
 */
function createGlowTexture() {
  const size = 128
  const canvas = document.createElement('canvas')
  canvas.width = size
  canvas.height = size
  const ctx = canvas.getContext('2d')
  if (ctx) {
    const gradient = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2)
    gradient.addColorStop(0, 'rgba(255,255,255,0.95)')
    gradient.addColorStop(0.25, 'rgba(255,255,255,0.35)')
    gradient.addColorStop(0.6, 'rgba(255,255,255,0.08)')
    gradient.addColorStop(1, 'rgba(255,255,255,0)')
    ctx.fillStyle = gradient
    ctx.fillRect(0, 0, size, size)
  }
  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  return texture
}

interface TooltipState {
  index: number
  x: number
  y: number
  pinned: boolean
}

export default function LandingNetworkScene() {
  const mountRef = useRef<HTMLDivElement>(null)
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)
  // The render loop lives outside React, so it pushes tooltip updates through a
  // ref-stable callback and only when the hovered node actually changes.
  const tooltipRef = useRef<TooltipState | null>(null)

  const publishTooltip = useCallback((next: TooltipState | null) => {
    const previous = tooltipRef.current
    if (!next && !previous) return
    if (
      next && previous &&
      next.index === previous.index &&
      next.pinned === previous.pinned &&
      Math.abs(next.x - previous.x) < 1 &&
      Math.abs(next.y - previous.y) < 1
    ) return
    tooltipRef.current = next
    setTooltip(next)
  }, [])

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let frame = 0
    let running = true
    // Reduced motion renders on demand only: no idle GPU work.
    let dirty = true

    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x07111f, 0.095)

    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100)
    camera.position.set(0, 0.15, 9.2)

    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' })
    } catch {
      // The fallback gradient is styled on the wrapper (.lp-network-canvas),
      // which is the mount's parent.
      mount.parentElement?.setAttribute('data-webgl', 'unavailable')
      return
    }

    renderer.setClearColor(0x000000, 0)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    renderer.domElement.setAttribute('aria-hidden', 'true')
    mount.appendChild(renderer.domElement)

    // `network` carries the pointer parallax tilt; `graphGroup` carries the
    // continuous auto-spin. Splitting them keeps the two motions independent so
    // the parallax never fights the rotation.
    const network = new THREE.Group()
    network.rotation.x = -0.08
    scene.add(network)

    const graphGroup = new THREE.Group()
    network.add(graphGroup)

    const linePositions: number[] = []
    EDGES.forEach(([from, to]) => {
      const a = NODE_POSITIONS[from]
      const b = NODE_POSITIONS[to]
      linePositions.push(a[0], a[1], a[2], b[0], b[1], b[2])
    })
    const lineGeometry = new THREE.BufferGeometry()
    lineGeometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3))
    const lineMaterial = new THREE.LineBasicMaterial({ color: 0x3b82f6, transparent: true, opacity: 0.24 })
    const lines = new THREE.LineSegments(lineGeometry, lineMaterial)
    graphGroup.add(lines)

    const attackEdges = [EDGES[3], EDGES[8], EDGES[16], EDGES[24]].filter(Boolean)
    const attackPositions: number[] = []
    attackEdges.forEach(([from, to]) => {
      const a = NODE_POSITIONS[from]
      const b = NODE_POSITIONS[to]
      attackPositions.push(a[0], a[1], a[2], b[0], b[1], b[2])
    })
    const attackGeometry = new THREE.BufferGeometry()
    attackGeometry.setAttribute('position', new THREE.Float32BufferAttribute(attackPositions, 3))
    const attackMaterial = new THREE.LineBasicMaterial({ color: 0xfb7185, transparent: true, opacity: 0.58 })
    graphGroup.add(new THREE.LineSegments(attackGeometry, attackMaterial))

    const nodeGeometry = new THREE.IcosahedronGeometry(0.095, 1)
    const nodeMaterial = new THREE.MeshBasicMaterial({ color: 0xffffff })
    const nodes = new THREE.InstancedMesh(nodeGeometry, nodeMaterial, NODE_POSITIONS.length)
    const dummy = new THREE.Object3D()
    NODE_POSITIONS.forEach((position, index) => {
      dummy.position.set(position[0], position[1], position[2])
      dummy.rotation.set(0, 0, 0)
      dummy.scale.setScalar(nodeScale(index))
      dummy.updateMatrix()
      nodes.setMatrixAt(index, dummy.matrix)
      nodes.setColorAt(index, new THREE.Color(nodeColor(index)))
    })
    nodes.instanceMatrix.needsUpdate = true
    if (nodes.instanceColor) nodes.instanceColor.needsUpdate = true
    graphGroup.add(nodes)

    // --- Horizontal "security rings" -------------------------------------
    // One flat arc per node, laid on the XZ plane and spun about its own Y axis.
    // The arc (rather than a closed ring) is what makes the spin readable, so it
    // scans like an orbital tracker instead of sitting still.
    const ringGeometry = new THREE.RingGeometry(0.155, 0.185, 48, 1, 0, Math.PI * 1.55)
    const ringMaterial = new THREE.MeshBasicMaterial({
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
    const rings = new THREE.InstancedMesh(ringGeometry, ringMaterial, NODE_POSITIONS.length)
    // Additive blending means per-instance colour doubles as per-instance
    // brightness, which is how hover/pulse emphasis is applied below.
    NODE_POSITIONS.forEach((_, index) => rings.setColorAt(index, new THREE.Color(nodeColor(index))))
    graphGroup.add(rings)

    const flatQuaternion = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1, 0, 0), Math.PI / 2)
    const spinQuaternion = new THREE.Quaternion()
    const spinAxis = new THREE.Vector3(0, 1, 0)
    const ringColor = new THREE.Color()

    const writeRings = (elapsed: number, hovered: number | null) => {
      NODE_POSITIONS.forEach((position, index) => {
        const scale = nodeScale(index)
        const phase = index * 0.79
        const pulse = reducedMotion ? 1 : 1 + Math.sin(elapsed * 1.9 + phase) * 0.08
        const focus = hovered === index ? 1.42 : 1
        dummy.position.set(position[0], position[1], position[2])
        spinQuaternion.setFromAxisAngle(spinAxis, reducedMotion ? phase : elapsed * (0.5 + index * 0.05) + phase)
        dummy.quaternion.copy(spinQuaternion).multiply(flatQuaternion)
        dummy.scale.setScalar(scale * 1.65 * pulse * focus)
        dummy.updateMatrix()
        rings.setMatrixAt(index, dummy.matrix)

        const brightness = hovered === index ? 1.6 : index === THREAT_INDEX ? 1.15 : 0.72
        ringColor.set(nodeColor(index)).multiplyScalar(brightness)
        rings.setColorAt(index, ringColor)
      })
      rings.instanceMatrix.needsUpdate = true
      if (rings.instanceColor) rings.instanceColor.needsUpdate = true
    }

    // --- Additive glow halos ---------------------------------------------
    const glowTexture = createGlowTexture()
    const glowSprites = NODE_POSITIONS.map((position, index) => {
      const material = new THREE.SpriteMaterial({
        map: glowTexture,
        color: nodeColor(index),
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        opacity: index === THREAT_INDEX ? 0.6 : 0.38,
      })
      const sprite = new THREE.Sprite(material)
      sprite.position.set(position[0], position[1], position[2])
      sprite.scale.setScalar(nodeScale(index) * (index === THREAT_INDEX ? 1.5 : 1.05))
      graphGroup.add(sprite)
      return sprite
    })

    // --- Invisible pick targets ------------------------------------------
    // Raycasting the 0.095-radius node geometry would demand pixel-precision, so
    // hover tests run against a larger transparent proxy instead.
    const pickGeometry = new THREE.SphereGeometry(0.3, 12, 12)
    const pickMaterial = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false })
    const pickMesh = new THREE.InstancedMesh(pickGeometry, pickMaterial, NODE_POSITIONS.length)
    NODE_POSITIONS.forEach((position, index) => {
      dummy.position.set(position[0], position[1], position[2])
      dummy.quaternion.identity()
      dummy.scale.setScalar(Math.max(nodeScale(index), 1))
      dummy.updateMatrix()
      pickMesh.setMatrixAt(index, dummy.matrix)
    })
    pickMesh.instanceMatrix.needsUpdate = true
    // Metadata rides on the object itself, mirroring the mesh.userData pattern.
    pickMesh.userData.meta = NODE_META
    graphGroup.add(pickMesh)

    const threatPosition = vectorAt(THREAT_INDEX)
    const threatGeometry = new THREE.RingGeometry(0.17, 0.2, 36)
    const threatMaterial = new THREE.MeshBasicMaterial({ color: 0xfb7185, transparent: true, opacity: 0.72, side: THREE.DoubleSide })
    const threatRing = new THREE.Mesh(threatGeometry, threatMaterial)
    threatRing.position.copy(threatPosition)
    graphGroup.add(threatRing)

    const packetGeometry = new THREE.SphereGeometry(0.042, 8, 8)
    const packetMaterial = new THREE.MeshBasicMaterial({ color: 0xe0f2fe })
    const packets = new THREE.InstancedMesh(packetGeometry, packetMaterial, PACKET_EDGES.length)
    graphGroup.add(packets)

    const dustCount = 90
    const dustPositions = new Float32Array(dustCount * 3)
    for (let index = 0; index < dustCount; index += 1) {
      dustPositions[index * 3] = (Math.sin(index * 91.7) * 0.5) * 9
      dustPositions[index * 3 + 1] = (Math.sin(index * 47.1) * 0.5) * 6
      dustPositions[index * 3 + 2] = -1.5 - Math.abs(Math.sin(index * 17.3)) * 3
    }
    const dustGeometry = new THREE.BufferGeometry()
    dustGeometry.setAttribute('position', new THREE.BufferAttribute(dustPositions, 3))
    const dustMaterial = new THREE.PointsMaterial({ color: 0x60a5fa, size: 0.018, transparent: true, opacity: 0.38 })
    const dust = new THREE.Points(dustGeometry, dustMaterial)
    scene.add(dust)

    const grid = new THREE.GridHelper(13, 20, 0x2563eb, 0x1e3a8a)
    grid.material.transparent = true
    grid.material.opacity = 0.1
    grid.rotation.x = Math.PI / 2
    grid.position.z = -2.7
    scene.add(grid)

    // --- Pointer + raycasting -------------------------------------------
    const raycaster = new THREE.Raycaster()
    const ndc = new THREE.Vector2()
    const parallax = { x: 0, y: 0 }
    let pointerInside = false
    let pointerLocal: { x: number; y: number } | null = null
    let hovered: number | null = null
    let pinned: number | null = null

    const readPointer = (event: PointerEvent) => {
      const rect = mount.getBoundingClientRect()
      const localX = event.clientX - rect.left
      const localY = event.clientY - rect.top
      pointerLocal = { x: localX, y: localY }
      ndc.x = (localX / rect.width) * 2 - 1
      ndc.y = -(localY / rect.height) * 2 + 1
      parallax.x = (localX / rect.width - 0.5) * 0.22
      parallax.y = (localY / rect.height - 0.5) * 0.16
      pointerInside = true
      dirty = true
    }

    const onPointerMove = (event: PointerEvent) => readPointer(event)

    const onPointerDown = (event: PointerEvent) => {
      readPointer(event)
      // Touch has no hover state, so the tap itself resolves the hit and pins it.
      const hit = pick()
      pinned = hit !== null && hit === pinned ? null : hit
      hovered = hit
      emitTooltip()
      dirty = true
    }

    const onPointerLeave = () => {
      pointerInside = false
      pointerLocal = null
      hovered = null
      parallax.x = 0
      parallax.y = 0
      if (pinned === null) publishTooltip(null)
      dirty = true
    }

    const pick = () => {
      if (!pointerInside) return null
      raycaster.setFromCamera(ndc, camera)
      const hits = raycaster.intersectObject(pickMesh, false)
      const instanceId = hits[0]?.instanceId
      return instanceId === undefined ? null : instanceId
    }

    const emitTooltip = () => {
      const index = hovered ?? pinned
      if (index === null) {
        publishTooltip(null)
        return
      }
      // Hover tooltips follow the cursor; a pinned tooltip (tap or click) stays
      // anchored to the node's projected screen position as the graph spins.
      let x: number
      let y: number
      if (hovered !== null && pointerLocal) {
        x = pointerLocal.x
        y = pointerLocal.y
      } else {
        const rect = mount.getBoundingClientRect()
        const projected = vectorAt(index)
        graphGroup.updateWorldMatrix(true, false)
        projected.applyMatrix4(graphGroup.matrixWorld).project(camera)
        x = (projected.x * 0.5 + 0.5) * rect.width
        y = (-projected.y * 0.5 + 0.5) * rect.height
      }
      publishTooltip({ index, x, y, pinned: pinned === index })
    }

    mount.addEventListener('pointermove', onPointerMove, { passive: true })
    mount.addEventListener('pointerdown', onPointerDown)
    mount.addEventListener('pointerleave', onPointerLeave)

    const resize = () => {
      const width = Math.max(mount.clientWidth, 1)
      const height = Math.max(mount.clientHeight, 1)
      renderer.setSize(width, height, false)
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      dirty = true
    }
    const resizeObserver = new ResizeObserver(resize)
    resizeObserver.observe(mount)
    resize()

    const intersectionObserver = new IntersectionObserver(([entry]) => {
      running = entry?.isIntersecting ?? true
    }, { rootMargin: '120px' })
    intersectionObserver.observe(mount)

    const clock = new THREE.Clock()
    let lastElapsed = 0
    const renderFrame = () => {
      frame = window.requestAnimationFrame(renderFrame)
      if (!running) return
      if (reducedMotion && !dirty) return

      const elapsed = clock.getElapsedTime()
      // Derived by hand: Clock.getElapsedTime() already consumes the internal
      // delta, so calling getDelta() after it would always return ~0.
      const delta = Math.min(elapsed - lastElapsed, 0.1)
      lastElapsed = elapsed

      if (!reducedMotion) {
        graphGroup.rotation.y += AUTO_SPIN_SPEED * delta
        network.rotation.y += (parallax.x - network.rotation.y) * 0.035
        network.rotation.x += (-parallax.y - 0.08 - network.rotation.x) * 0.035
        dust.rotation.z = elapsed * 0.006
      }

      const nextHovered = pick()
      if (nextHovered !== hovered) {
        hovered = nextHovered
        dirty = true
      }
      emitTooltip()

      writeRings(elapsed, hovered ?? pinned)

      glowSprites.forEach((sprite, index) => {
        const focus = (hovered ?? pinned) === index
        const base = nodeScale(index) * (index === THREAT_INDEX ? 1.5 : 1.05)
        const breathe = reducedMotion ? 1 : 1 + Math.sin(elapsed * 1.6 + index) * 0.07
        sprite.scale.setScalar(base * breathe * (focus ? 1.5 : 1))
        sprite.material.opacity = focus ? 0.72 : index === THREAT_INDEX ? 0.6 : 0.38
      })

      const pulse = 1 + (reducedMotion ? 0 : Math.sin(elapsed * 2.2) * 0.16)
      threatRing.scale.setScalar(pulse)
      threatMaterial.opacity = 0.48 + (reducedMotion ? 0.2 : Math.sin(elapsed * 2.2) * 0.2)
      threatRing.lookAt(camera.position)

      PACKET_EDGES.forEach((edgeIndex, packetIndex) => {
        const edge = EDGES[edgeIndex]
        const start = vectorAt(edge[0])
        const end = vectorAt(edge[1])
        const progress = reducedMotion
          ? 0.42
          : (elapsed * (0.12 + packetIndex * 0.008) + packetIndex / PACKET_EDGES.length) % 1
        dummy.position.lerpVectors(start, end, progress)
        dummy.quaternion.identity()
        dummy.scale.setScalar(1)
        dummy.updateMatrix()
        packets.setMatrixAt(packetIndex, dummy.matrix)
      })
      packets.instanceMatrix.needsUpdate = true

      renderer.render(scene, camera)
      dirty = false
    }

    renderFrame()

    return () => {
      window.cancelAnimationFrame(frame)
      resizeObserver.disconnect()
      intersectionObserver.disconnect()
      mount.removeEventListener('pointermove', onPointerMove)
      mount.removeEventListener('pointerdown', onPointerDown)
      mount.removeEventListener('pointerleave', onPointerLeave)
      lineGeometry.dispose()
      lineMaterial.dispose()
      attackGeometry.dispose()
      attackMaterial.dispose()
      nodeGeometry.dispose()
      nodeMaterial.dispose()
      ringGeometry.dispose()
      ringMaterial.dispose()
      pickGeometry.dispose()
      pickMaterial.dispose()
      glowSprites.forEach((sprite) => sprite.material.dispose())
      glowTexture.dispose()
      threatGeometry.dispose()
      threatMaterial.dispose()
      packetGeometry.dispose()
      packetMaterial.dispose()
      dustGeometry.dispose()
      dustMaterial.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [publishTooltip])

  const meta = tooltip ? NODE_META[tooltip.index] : null

  return (
    <div
      className="lp-network-canvas"
      role="img"
      aria-label="Abstract ambient host network showing signal flow and a highlighted threat path"
    >
      <div ref={mountRef} className="lp-network-mount" />
      {meta && tooltip && (
        <div
          className={`lp-node-tooltip${tooltip.pinned ? ' is-pinned' : ''}`}
          style={{ left: `${tooltip.x}px`, top: `${tooltip.y}px` }}
          aria-hidden="true"
        >
          <span className="lp-node-tooltip-title">
            {meta.label}
            {tooltip.index === THREAT_INDEX && <i className="is-threat" />}
          </span>
          <span className="lp-node-tooltip-row">{meta.zone} · {meta.role}</span>
          <span className="lp-node-tooltip-row">{LINK_COUNTS[tooltip.index]} links · {meta.status}</span>
          <small>Illustrative topology · no capture loaded</small>
        </div>
      )}
    </div>
  )
}
