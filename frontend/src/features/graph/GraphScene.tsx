import { Html, OrbitControls } from '@react-three/drei'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'

import type { GraphEdge3D, GraphModel, GraphNode3D } from '@/features/graph/graphModel'
import { EDGE_COLOR, RISK_COLOR, SCENE_BACKGROUND } from '@/features/graph/graphTheme'

const QUIET_EDGE = new THREE.Color(EDGE_COLOR.quiet)
const RISK_EDGE = new THREE.Color(EDGE_COLOR.risky)

interface ReplayFocus {
  /** Hosts alerting in the window under the cursor. */
  activeHosts: Set<string>
  /** Hosts that have alerted at or before the cursor. */
  seenHosts: Set<string>
  /** Stage of each active host's current alert, for stage emphasis. */
  stageByHost: Map<string, string>
  cursorLabel: string
}

interface SceneProps {
  model: GraphModel
  selected: string | null
  onSelect: (ip: string | null) => void
  reduceMotion: boolean
  /** Null when the analyst has not engaged the timeline. */
  replay: ReplayFocus | null
}

function nodeScale(node: GraphNode3D): number {
  // Size is driven by peak probability (the analyst's ranking signal), with a
  // floor so a quiet host is still clickable.
  return 0.13 + node.peakProb * 0.2
}

function Edges({ edges, activeHosts }: { edges: GraphEdge3D[]; activeHosts: Set<string> | null }) {
  const geometry = useMemo(() => {
    const positions = new Float32Array(edges.length * 6)
    const colors = new Float32Array(edges.length * 6)
    edges.forEach((edge, index) => {
      const offset = index * 6
      positions[offset] = edge.from.x
      positions[offset + 1] = edge.from.y
      positions[offset + 2] = edge.from.z
      positions[offset + 3] = edge.to.x
      positions[offset + 4] = edge.to.y
      positions[offset + 5] = edge.to.z

      const risky = edge.risk > 0
      const base = risky ? RISK_EDGE : QUIET_EDGE
      // Weight modulates brightness, so a heavy relationship reads stronger
      // without faking line width (WebGL lines ignore linewidth).
      let lift = 0.45 + 0.55 * edge.weightScale
      if (risky) lift = Math.max(lift, 0.7)
      // Replay: graph edges are capture-aggregate with no per-window timestamps,
      // so "active" can only mean "its source host is alerting right now".
      if (activeHosts) {
        lift = activeHosts.has(edge.src) ? 1.15 : lift * 0.22
      }
      const color = base.clone().multiplyScalar(lift)
      colors[offset] = color.r
      colors[offset + 1] = color.g
      colors[offset + 2] = color.b
      colors[offset + 3] = color.r
      colors[offset + 4] = color.g
      colors[offset + 5] = color.b
    })

    const buffer = new THREE.BufferGeometry()
    buffer.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    buffer.setAttribute('color', new THREE.BufferAttribute(colors, 3))
    return buffer
  }, [activeHosts, edges])

  useEffect(() => () => geometry.dispose(), [geometry])

  return (
    <lineSegments geometry={geometry} frustumCulled={false}>
      <lineBasicMaterial vertexColors transparent opacity={0.75} />
    </lineSegments>
  )
}

interface NodeProps {
  node: GraphNode3D
  selected: boolean
  hovered: boolean
  reduceMotion: boolean
  /** null = no replay; otherwise how this host stands at the cursor. */
  replayState: { active: boolean; seen: boolean; stageColor: string | null } | null
  onSelect: (ip: string) => void
  onHover: (ip: string | null) => void
}

function HostNode({
  node,
  selected,
  hovered,
  reduceMotion,
  replayState,
  onSelect,
  onHover,
}: NodeProps) {
  const mesh = useRef<THREE.Mesh>(null)
  const base = nodeScale(node)
  const color = RISK_COLOR[node.risk]

  // Under replay, a host that has not acted yet fades back instead of vanishing,
  // so the analyst still sees the topology.
  const dimmed = replayState !== null && !replayState.active && !replayState.seen
  const opacity = dimmed ? 0.18 : 1

  useFrame((state) => {
    if (!mesh.current) return
    const pulsing =
      !reduceMotion && (replayState ? replayState.active : node.risk === 'high')
    if (pulsing) {
      const pulse = 1 + Math.sin(state.clock.elapsedTime * 2.1) * 0.07
      mesh.current.scale.setScalar(pulse)
    } else {
      mesh.current.scale.setScalar(1)
    }
  })

  const emissiveIntensity = replayState?.active
    ? 1
    : node.risk === 'high'
      ? 0.85
      : node.risk === 'alerting'
        ? 0.42
        : 0.08

  const showLabel =
    selected || hovered || (replayState ? replayState.active : node.risk === 'high')

  return (
    <group position={[node.x, node.y, node.z]}>
      <mesh
        ref={mesh}
        onPointerOver={(event) => {
          event.stopPropagation()
          onHover(node.ip)
        }}
        onPointerOut={() => onHover(null)}
        onClick={(event) => {
          event.stopPropagation()
          onSelect(node.ip)
        }}
      >
        {node.zone === 'internal' ? (
          <icosahedronGeometry args={[base, 2]} />
        ) : node.zone === 'external' ? (
          <boxGeometry args={[base * 1.6, base * 1.6, base * 1.6]} />
        ) : (
          <octahedronGeometry args={[base * 1.15, 0]} />
        )}
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={emissiveIntensity}
          metalness={0.15}
          roughness={0.45}
          transparent={dimmed}
          opacity={opacity}
        />
      </mesh>

      {/* Stage emphasis while a host is alerting at the cursor. */}
      {replayState?.active && replayState.stageColor && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[base * 1.9, 0.02, 8, 48]} />
          <meshBasicMaterial color={replayState.stageColor} />
        </mesh>
      )}

      {/* Selection focus ring — a shape cue, not just a colour change. */}
      {selected && (
        <mesh rotation={[Math.PI / 2.4, 0, 0]}>
          <torusGeometry args={[base * 2.4, 0.012, 8, 48]} />
          <meshBasicMaterial color="#38bdf8" />
        </mesh>
      )}

      {showLabel && (
        <Html center={false} distanceFactor={9} zIndexRange={[10, 0]}>
          <div className={`graph-node-label${node.risk === 'high' ? ' is-high' : ''}`}>
            {node.ip}
            {node.alerts > 0 ? ` · ${(node.peakProb * 100).toFixed(0)}%` : ''}
          </div>
        </Html>
      )}
    </group>
  )
}

/** Eases the orbit target and camera onto the selected node. */
function FocusRig({
  target,
  reduceMotion,
  controls,
}: {
  target: GraphNode3D | null
  reduceMotion: boolean
  controls: React.MutableRefObject<{ target: THREE.Vector3; update: () => void } | null>
}) {
  const { camera } = useThree()
  const desired = useRef(new THREE.Vector3())
  const active = useRef(false)

  useEffect(() => {
    if (!target) {
      active.current = false
      return
    }
    desired.current.set(target.x, target.y, target.z)
    active.current = true

    if (reduceMotion && controls.current) {
      controls.current.target.copy(desired.current)
      const offset = new THREE.Vector3(1.6, 1.2, 1.6)
      camera.position.copy(desired.current.clone().add(offset))
      controls.current.update()
      active.current = false
    }
  }, [camera, controls, reduceMotion, target])

  useFrame(() => {
    if (!active.current || !controls.current) return
    const current = controls.current.target
    current.lerp(desired.current, 0.12)
    if (current.distanceTo(desired.current) < 0.02) active.current = false
    controls.current.update()
  })

  return null
}

/** Frames the whole cloud once, so the graph never opens off-centre. */
function FitCamera({
  radius,
  controls,
}: {
  radius: number
  controls: React.MutableRefObject<{ target: THREE.Vector3; update: () => void } | null>
}) {
  const { camera } = useThree()
  const done = useRef(false)

  useFrame(() => {
    if (done.current || !controls.current) return
    const distance = Math.max(radius * 2.1, 3.4)
    camera.position.set(distance * 0.62, distance * 0.48, distance * 0.78)
    camera.lookAt(0, 0, 0)
    controls.current.target.set(0, 0, 0)
    controls.current.update()
    done.current = true
  })

  return null
}

export function GraphScene({ model, selected, onSelect, reduceMotion, replay }: SceneProps) {
  const [hovered, setHovered] = useState<string | null>(null)
  const controls = useRef<{ target: THREE.Vector3; update: () => void } | null>(null)
  const selectedNode = model.nodes.find((node) => node.ip === selected) ?? null

  return (
    <Canvas
      // DPR is capped: a retina display would otherwise render 4x the pixels.
      dpr={[1, 1.6]}
      camera={{ position: [6.4, 4.6, 7.2], fov: 46, near: 0.1, far: 120 }}
      gl={{ antialias: true, powerPreference: 'high-performance' }}
      onPointerMissed={() => onSelect(null)}
    >
      <color attach="background" args={[SCENE_BACKGROUND]} />
      <fog attach="fog" args={[SCENE_BACKGROUND, 12, 30]} />

      <ambientLight intensity={0.55} />
      <directionalLight position={[6, 8, 5]} intensity={0.7} />
      <pointLight position={[-6, -4, -6]} intensity={0.35} color="#38bdf8" />

      <Edges edges={model.edges} activeHosts={replay?.activeHosts ?? null} />

      {model.nodes.map((node) => (
        <HostNode
          key={node.ip}
          node={node}
          selected={node.ip === selected}
          hovered={node.ip === hovered}
          reduceMotion={reduceMotion}
          replayState={
            replay
              ? {
                  active: replay.activeHosts.has(node.ip),
                  seen: replay.seenHosts.has(node.ip),
                  stageColor: replay.stageByHost.get(node.ip) ?? null,
                }
              : null
          }
          onSelect={onSelect}
          onHover={setHovered}
        />
      ))}

      <FocusRig target={selectedNode} reduceMotion={reduceMotion} controls={controls} />
      <FitCamera radius={model.radius} controls={controls} />

      <OrbitControls
        ref={controls as never}
        enablePan
        enableZoom
        enableDamping={!reduceMotion}
        dampingFactor={0.08}
        autoRotate={false}
        minDistance={1.6}
        maxDistance={34}
      />
    </Canvas>
  )
}
