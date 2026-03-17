import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { cn } from '@/lib/utils'

interface CodeBlockProps {
  code: string
  language?: string
  filename?: string
  className?: string
  showLineNumbers?: boolean
}

// Simple syntax highlighter for static, developer-authored code snippets only.
// All input is first HTML-escaped to prevent injection.
function highlightSyntax(code: string, language?: string): string {
  let result = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

  // Comments
  result = result.replace(
    /(\/\/.*$|#.*$)/gm,
    '<span class="token-comment">$1</span>'
  )

  // Strings (using &quot; since we escaped earlier)
  result = result.replace(
    /(&quot;(?:[^&]|&(?!quot;))*&quot;|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g,
    '<span class="token-string">$1</span>'
  )

  // Numbers
  result = result.replace(
    /\b(\d+\.?\d*)\b/g,
    '<span class="token-number">$1</span>'
  )

  if (language === 'go' || language === 'golang') {
    const goKeywords = ['package', 'import', 'func', 'return', 'if', 'else', 'for', 'range', 'var', 'const', 'type', 'struct', 'interface', 'map', 'chan', 'go', 'defer', 'select', 'case', 'switch', 'default', 'break', 'continue', 'nil', 'true', 'false', 'err']
    goKeywords.forEach((kw) => {
      result = result.replace(
        new RegExp(`\\b(${kw})\\b`, 'g'),
        '<span class="token-keyword">$1</span>'
      )
    })
  } else if (language === 'yaml' || language === 'yml') {
    result = result.replace(
      /^(\s*[\w.-]+)(:)/gm,
      '<span class="token-property">$1</span><span class="token-punctuation">$2</span>'
    )
    result = result.replace(
      /\b(true|false|yes|no|null)\b/gi,
      '<span class="token-keyword">$1</span>'
    )
  } else if (language === 'bash' || language === 'sh' || language === 'shell') {
    const bashKeywords = ['curl', 'wget', 'sudo', 'apt', 'yum', 'brew', 'go', 'docker', 'guardianwaf']
    bashKeywords.forEach((kw) => {
      result = result.replace(
        new RegExp(`\\b(${kw})\\b`, 'g'),
        '<span class="token-function">$1</span>'
      )
    })
    result = result.replace(
      /(\s)(--?[\w-]+)/g,
      '$1<span class="token-flag">$2</span>'
    )
  } else if (language === 'json') {
    result = result.replace(
      /\b(true|false|null)\b/g,
      '<span class="token-keyword">$1</span>'
    )
  }

  return result
}

export function CodeBlock({
  code,
  language,
  filename,
  className,
  showLineNumbers = false,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const highlighted = highlightSyntax(code, language)
  const lines = highlighted.split('\n')

  return (
    <div
      className={cn(
        'group relative rounded-lg border border-border bg-card overflow-hidden',
        className
      )}
    >
      {filename && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-background/50">
          <span className="text-xs text-muted font-mono">{filename}</span>
          {language && (
            <span className="text-xs text-muted">{language}</span>
          )}
        </div>
      )}
      <div className="relative">
        <button
          onClick={handleCopy}
          className="absolute right-2 top-2 p-2 rounded-md bg-card/80 border border-border opacity-0 group-hover:opacity-100 transition-opacity duration-200 hover:bg-border/50 cursor-pointer"
          aria-label="Copy code"
        >
          {copied ? (
            <Check className="h-4 w-4 text-success" />
          ) : (
            <Copy className="h-4 w-4 text-muted" />
          )}
        </button>
        {/*
          Safety note: highlightSyntax only processes developer-authored code constants.
          All input is HTML-escaped before any span tags are added.
        */}
        <pre className="overflow-x-auto p-4 text-sm leading-relaxed">
          <code className="font-mono">
            {lines.map((line, i) => (
              <div key={i} className="flex">
                {showLineNumbers && (
                  <span className="inline-block w-8 text-right mr-4 text-muted-foreground select-none shrink-0">
                    {i + 1}
                  </span>
                )}
                <span dangerouslySetInnerHTML={{ __html: line || '\n' }} />
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  )
}
