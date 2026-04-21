import { useState, useRef, useCallback, type ReactNode } from 'react'
import { clsx } from 'clsx'

interface SplitPaneProps {
  left: ReactNode
  right: ReactNode
  direction?: 'horizontal' | 'vertical'
  defaultSplit?: number
  className?: string
}

export function SplitPane({ left, right, direction = 'horizontal', defaultSplit = 50, className }: SplitPaneProps) {
  const [split, setSplit] = useState(defaultSplit)
  const containerRef = useRef<HTMLDivElement>(null)
  const dragging = useRef(false)

  const onMouseDown = useCallback(() => {
    dragging.current = true
    document.body.style.cursor = direction === 'horizontal' ? 'col-resize' : 'row-resize'
    document.body.style.userSelect = 'none'
  }, [direction])

  const onMouseMove = useCallback((e: MouseEvent) => {
    if (!dragging.current || !containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    let pct: number
    if (direction === 'horizontal') {
      pct = ((e.clientX - rect.left) / rect.width) * 100
    } else {
      pct = ((e.clientY - rect.top) / rect.height) * 100
    }
    setSplit(Math.max(10, Math.min(90, pct)))
  }, [direction])

  const onMouseUp = useCallback(() => {
    dragging.current = false
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
  }, [])

  // Attach global listeners
  useCallback(() => {
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [onMouseMove, onMouseUp])

  const isH = direction === 'horizontal'

  return (
    <div
      ref={containerRef}
      className={clsx('flex overflow-hidden', isH ? 'flex-row' : 'flex-col', className)}
      onMouseMove={onMouseMove as unknown as React.MouseEventHandler}
      onMouseUp={onMouseUp as unknown as React.MouseEventHandler}
    >
      <div
        className="overflow-auto"
        style={isH ? { width: `${split}%` } : { height: `${split}%` }}
      >
        {left}
      </div>
      <div
        className={clsx(
          'shrink-0 bg-bg-border hover:bg-accent/50 transition-colors cursor-col-resize z-10',
          isH ? 'w-px cursor-col-resize hover:w-1' : 'h-px cursor-row-resize hover:h-1'
        )}
        onMouseDown={onMouseDown}
      />
      <div className="flex-1 overflow-auto">
        {right}
      </div>
    </div>
  )
}
