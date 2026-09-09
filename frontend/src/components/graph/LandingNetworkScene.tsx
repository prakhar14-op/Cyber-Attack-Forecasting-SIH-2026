import { useEffect, useRef } from 'react'
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

function vectorAt(index: number) {
  const position = NODE_POSITIONS[index]
  if (!position) return new THREE.Vector3()
  return new THREE.Vector3(position[0], position[1], position[2])
}

export default function LandingNetworkScene() {
  const mountRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return

    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let frame = 0
    let running = true

    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x07111f, 0.095)

    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100)
    camera.position.set(0, 0.15, 9.2)

    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' })
    } catch {
      mount.dataset.webgl = 'unavailable'
      return
    }

    renderer.setClearColor(0x000000, 0)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    renderer.domElement.setAttribute('aria-hidden', 'true')
    mount.appendChild(renderer.domElement)

    const network = new THREE.Group()
    network.rotation.x = -0.08
    scene.add(network)

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
    network.add(lines)

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
    network.add(new THREE.LineSegments(attackGeometry, attackMaterial))

    const nodeGeometry = new THREE.IcosahedronGeometry(0.095, 1)
    const nodeMaterial = new THREE.MeshBasicMaterial({ color: 0x7dd3fc })
    const nodes = new THREE.InstancedMesh(nodeGeometry, nodeMaterial, NODE_POSITIONS.length)
    const dummy = new THREE.Object3D()
    NODE_POSITIONS.forEach((position, index) => {
      dummy.position.set(position[0], position[1], position[2])
      const scale = index === 7 ? 1.55 : index % 5 === 0 ? 1.2 : 0.86
      dummy.scale.setScalar(scale)
      dummy.updateMatrix()
      nodes.setMatrixAt(index, dummy.matrix)
      nodes.setColorAt(index, new THREE.Color(index === 7 ? 0xfb7185 : index % 4 === 0 ? 0xa78bfa : 0x7dd3fc))
    })
    nodes.instanceMatrix.needsUpdate = true
    if (nodes.instanceColor) {
      nodes.instanceColor.needsUpdate = true
    }
    network.add(nodes)

    const threatPosition = vectorAt(7)
    const threatGeometry = new THREE.RingGeometry(0.17, 0.2, 36)
    const threatMaterial = new THREE.MeshBasicMaterial({ color: 0xfb7185, transparent: true, opacity: 0.72, side: THREE.DoubleSide })
    const threatRing = new THREE.Mesh(threatGeometry, threatMaterial)
    threatRing.position.copy(threatPosition)
    network.add(threatRing)

    const packetGeometry = new THREE.SphereGeometry(0.042, 8, 8)
    const packetMaterial = new THREE.MeshBasicMaterial({ color: 0xe0f2fe })
    const packets = new THREE.InstancedMesh(packetGeometry, packetMaterial, PACKET_EDGES.length)
    network.add(packets)

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

    const pointer = { x: 0, y: 0 }
    const onPointerMove = (event: PointerEvent) => {
      const rect = mount.getBoundingClientRect()
      pointer.x = ((event.clientX - rect.left) / rect.width - 0.5) * 0.22
      pointer.y = ((event.clientY - rect.top) / rect.height - 0.5) * 0.16
    }
    mount.addEventListener('pointermove', onPointerMove, { passive: true })

    const resize = () => {
      const width = Math.max(mount.clientWidth, 1)
      const height = Math.max(mount.clientHeight, 1)
      renderer.setSize(width, height, false)
      camera.aspect = width / height
      camera.updateProjectionMatrix()
    }
    const resizeObserver = new ResizeObserver(resize)
    resizeObserver.observe(mount)
    resize()

    const intersectionObserver = new IntersectionObserver(([entry]) => {
      running = entry?.isIntersecting ?? true
    }, { rootMargin: '120px' })
    intersectionObserver.observe(mount)

    const clock = new THREE.Clock()
    const renderFrame = () => {
      frame = window.requestAnimationFrame(renderFrame)
      if (!running) return

      const elapsed = clock.getElapsedTime()
      network.rotation.y += (pointer.x - network.rotation.y) * 0.035
      network.rotation.x += (-pointer.y - 0.08 - network.rotation.x) * 0.035
      dust.rotation.z = elapsed * 0.006

      const pulse = 1 + Math.sin(elapsed * 2.2) * 0.16
      threatRing.scale.setScalar(pulse)
      threatMaterial.opacity = 0.48 + Math.sin(elapsed * 2.2) * 0.2
      threatRing.lookAt(camera.position)

      PACKET_EDGES.forEach((edgeIndex, packetIndex) => {
        const edge = EDGES[edgeIndex]
        const start = vectorAt(edge[0])
        const end = vectorAt(edge[1])
        const progress = (elapsed * (0.12 + packetIndex * 0.008) + packetIndex / PACKET_EDGES.length) % 1
        dummy.position.lerpVectors(start, end, progress)
        dummy.scale.setScalar(1)
        dummy.updateMatrix()
        packets.setMatrixAt(packetIndex, dummy.matrix)
      })
      packets.instanceMatrix.needsUpdate = true
      renderer.render(scene, camera)
    }

    if (reducedMotion) {
      PACKET_EDGES.forEach((edgeIndex, packetIndex) => {
        const edge = EDGES[edgeIndex]
        dummy.position.lerpVectors(vectorAt(edge[0]), vectorAt(edge[1]), 0.42)
        dummy.updateMatrix()
        packets.setMatrixAt(packetIndex, dummy.matrix)
      })
      packets.instanceMatrix.needsUpdate = true
      renderer.render(scene, camera)
    } else {
      renderFrame()
    }

    return () => {
      window.cancelAnimationFrame(frame)
      resizeObserver.disconnect()
      intersectionObserver.disconnect()
      mount.removeEventListener('pointermove', onPointerMove)
      lineGeometry.dispose()
      lineMaterial.dispose()
      attackGeometry.dispose()
      attackMaterial.dispose()
      nodeGeometry.dispose()
      nodeMaterial.dispose()
      threatGeometry.dispose()
      threatMaterial.dispose()
      packetGeometry.dispose()
      packetMaterial.dispose()
      dustGeometry.dispose()
      dustMaterial.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [])

  return <div ref={mountRef} className="lp-network-canvas" role="img" aria-label="Abstract ambient host network showing signal flow and a highlighted threat path" />
}
