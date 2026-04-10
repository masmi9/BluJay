import { Highlight, themes } from 'prism-react-renderer'

interface CodeBlockProps {
  code: string
  language?: string
  className?: string
}

export function CodeBlock({ code, language = 'markup', className }: CodeBlockProps) {
  return (
    <Highlight theme={themes.vsDark} code={code} language={language as any}>
      {({ className: cls, style, tokens, getLineProps, getTokenProps }) => (
        <pre
          className={`text-xs font-mono overflow-auto leading-5 p-3 bg-bg-base rounded ${className ?? ''}`}
          style={style}
        >
          {tokens.map((line, i) => (
            <div key={i} {...getLineProps({ line })}>
              <span className="select-none text-zinc-600 mr-4 text-right inline-block w-6">{i + 1}</span>
              {line.map((token, key) => (
                <span key={key} {...getTokenProps({ token })} />
              ))}
            </div>
          ))}
        </pre>
      )}
    </Highlight>
  )
}
